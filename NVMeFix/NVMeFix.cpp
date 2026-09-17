//
// @file NVMeFix.cpp
//
// NVMeFix
//
// Copyright © 2019 acidanthera. All rights reserved.
//
// This program and the accompanying materials
// are licensed and made available under the terms and conditions of the BSD License
// which accompanies this distribution.  The full text of the license may be found at
// http://opensource.org/licenses/bsd-license.php
// THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
// WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

#include <IOKit/IOService.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <kern/assert.h>
#include <kern/clock.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/libkern.h>
#include <mach-o/loader.h>

#include <Headers/kern_api.hpp>
#include <Headers/kern_disasm.hpp>
#include <Headers/kern_iokit.hpp>
#include <Headers/hde64.h>
#include <Headers/kern_util.hpp>
#include <Headers/plugin_start.hpp>

#include "Log.hpp"
#include "NVMeFixPlugin.hpp"

static NVMeFixPlugin plugin;

static constexpr uint8_t PM981aIONVMeUUID[16] {
	0xB2, 0x38, 0xDF, 0x16, 0x66, 0xB9, 0x36, 0x8F,
	0xBF, 0xF5, 0xC4, 0xD9, 0x92, 0xC8, 0x83, 0x1B
};
static constexpr char PM981aDiagnosticKey[] {
	"56685473-CFDB-4401-83D8-81E524BEAD22:nvmef-pm981a-diag"
};
static constexpr char PM981aModel[] {"SAMSUNG MZVLB256HBHQ-000L7"};
static constexpr char PM981aFirmware[] {"5M2QEXH7"};
static constexpr uint16_t PM981aVendor {0x144D};
static constexpr uint16_t PM981aDevice {0xA808};
static constexpr uint32_t PM981aSnapshotMagic {0x47443950}; // "P9DG" in little endian.
static constexpr uint16_t PM981aSnapshotVersion {1};

enum DiagnosticStorageState : unsigned {
	DiagnosticStorageUninitialised = 0,
	DiagnosticStorageInitialising = 1,
	DiagnosticStorageReady = 2,
	DiagnosticStorageOccupied = 3
};

NVMeFixPlugin& NVMeFixPlugin::globalPlugin() {
	return plugin;
}

/**
 * This may be invoked before or after we get IOBSD mount notification, so in the both functions we
 * attempt to solve symbols and handle the controllers.
 */
void NVMeFixPlugin::processKext(void* that, KernelPatcher& patcher, size_t index,
								mach_vm_address_t address, size_t size) {
	auto plugin = static_cast<NVMeFixPlugin*>(that);
	assert(plugin);

	if (index != plugin->kextInfo.loadIndex)
		return;

	DBGLOG(Log::Plugin, "processKext %s", plugin->kextInfo.id);

	const bool diagnosticsRequested = plugin->persistenceTestRequested ||
		plugin->runtimeDiagnosticsRequested;
	const bool exactImage = diagnosticsRequested && plugin->verifyDiagnosticImage(address, size);
	atomic_store_explicit(&plugin->diagnosticImageValid, exactImage, memory_order_release);

	// processKext is a normal execution context. An early best-effort attempt avoids relying on
	// controller discovery timing, while a transient early failure remains retryable after Identify.
	if (exactImage)
		plugin->prepareDiagnosticStorage();

	if (plugin->solveSymbols(patcher)) {
		if (exactImage && plugin->runtimeDiagnosticsRequested) {
			const bool routed = plugin->solveAndRouteDiagnostics(patcher, address, size);
			atomic_store_explicit(&plugin->diagnosticRoutesReady, routed, memory_order_release);
		}

		atomic_store_explicit(&plugin->solvedSymbols, true, memory_order_release);
		plugin->handleControllers();
	}
}

bool NVMeFixPlugin::verifyDiagnosticImage(mach_vm_address_t imageAddress, size_t imageSize) const {
	if (getKernelVersion() != KernelVersion::Sequoia || getKernelMinorVersion() != 4 ||
		imageAddress == 0 || imageSize < sizeof(mach_header_64))
		return false;

	auto header = reinterpret_cast<const mach_header_64*>(imageAddress);
	if (header->magic != MH_MAGIC_64 || header->filetype != MH_KEXT_BUNDLE ||
		header->sizeofcmds > imageSize - sizeof(*header) ||
		header->ncmds > header->sizeofcmds / sizeof(load_command))
		return false;

	auto command = reinterpret_cast<const uint8_t*>(header + 1);
	size_t remaining = header->sizeofcmds;
	bool foundUUID = false;

	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (remaining < sizeof(load_command))
			return false;

		auto loadCommand = reinterpret_cast<const load_command*>(command);
		if (loadCommand->cmdsize < sizeof(load_command) || loadCommand->cmdsize > remaining)
			return false;

		if (loadCommand->cmd == LC_UUID) {
			if (foundUUID || loadCommand->cmdsize < sizeof(uuid_command))
				return false;
			auto uuidCommand = reinterpret_cast<const uuid_command*>(loadCommand);
			if (memcmp(uuidCommand->uuid, PM981aIONVMeUUID, sizeof(PM981aIONVMeUUID)) != 0)
				return false;
			foundUUID = true;
		}

		command += loadCommand->cmdsize;
		remaining -= loadCommand->cmdsize;
	}

	return foundUUID;
}

bool NVMeFixPlugin::validateDiagnosticABI(mach_vm_address_t imageAddress, size_t imageSize) const {
	static constexpr uint8_t submitPrologue[] {
		0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50,
		0x49, 0x89, 0xD6, 0x49, 0x89, 0xF7, 0x48, 0x89, 0xFB
	};
	static constexpr uint8_t submitTail[] {
		0x48, 0x8B, 0xBB, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x08,
		0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D
	};
	static constexpr uint8_t filterPrologue[] {
		0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53, 0x48, 0x89, 0xFB
	};
	static constexpr uint8_t filterReturn[] {
		0x31, 0xC0, 0x5B, 0x41, 0x5E, 0x5D, 0xC3
	};
	static constexpr uint8_t handlerPrologue[] {
		0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50,
		0x48, 0x89, 0xFB
	};
	static constexpr uint8_t handlerReturn[] {
		0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
	};
	static constexpr uint8_t completionPrologue[] {
		0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
		0x41, 0x54, 0x53, 0x48, 0x83, 0xEC, 0x28
	};
	static constexpr uint8_t completionReturn[] {
		0x8B, 0x45, 0xCC, 0x48, 0x83, 0xC4, 0x28, 0x5B, 0x41, 0x5C,
		0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
	};
	static constexpr uint8_t timeoutPrologue[] {
		0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53, 0x48, 0x85, 0xF6
	};
	static constexpr uint8_t timeoutReturn[] {
		0x5B, 0x41, 0x5E, 0x5D, 0xC3
	};

	auto matches = [imageAddress, imageSize](mach_vm_address_t function, size_t offset,
											 const uint8_t* bytes, size_t byteCount) {
		if (!function || function < imageAddress)
			return false;
		const auto functionOffset = function - imageAddress;
		if (functionOffset > imageSize || offset > imageSize - functionOffset ||
			byteCount > imageSize - functionOffset - offset)
			return false;
		return memcmp(reinterpret_cast<const void*>(function + offset), bytes, byteCount) == 0;
	};

	return matches(kextFuncs.IONVMeController.SubmitCommand.fptr, 0, submitPrologue,
				   sizeof(submitPrologue)) &&
		matches(kextFuncs.IONVMeController.SubmitCommand.fptr, 0x69, submitTail,
				sizeof(submitTail)) &&
		matches(kextFuncs.IONVMeController.FilterInterruptRequest.fptr, 0, filterPrologue,
				sizeof(filterPrologue)) &&
		matches(kextFuncs.IONVMeController.FilterInterruptRequest.fptr, 0xFD, filterReturn,
				sizeof(filterReturn)) &&
		matches(kextFuncs.IONVMeController.HandleInterruptRequest.fptr, 0, handlerPrologue,
				sizeof(handlerPrologue)) &&
		matches(kextFuncs.IONVMeController.HandleInterruptRequest.fptr, 0x1A1, handlerReturn,
				sizeof(handlerReturn)) &&
		matches(kextFuncs.IONVMeController.ProcessCompletionQueue.fptr, 0, completionPrologue,
				sizeof(completionPrologue)) &&
		matches(kextFuncs.IONVMeController.ProcessCompletionQueue.fptr, 0x481, completionReturn,
				sizeof(completionReturn)) &&
		matches(kextFuncs.IONVMeController.CommandTimeout.fptr, 0, timeoutPrologue,
				sizeof(timeoutPrologue)) &&
		matches(kextFuncs.IONVMeController.CommandTimeout.fptr, 0x117, timeoutReturn,
				sizeof(timeoutReturn));
}

bool NVMeFixPlugin::solveAndRouteDiagnostics(KernelPatcher& kp, mach_vm_address_t imageAddress,
											 size_t imageSize) {
	auto idx = kextInfo.loadIndex;
	bool solved = kextFuncs.IONVMeController.SubmitCommand.solve(kp, idx) &&
		kextFuncs.IONVMeController.FilterInterruptRequest.solve(kp, idx) &&
		kextFuncs.IONVMeController.HandleInterruptRequest.solve(kp, idx) &&
		kextFuncs.IONVMeController.ProcessCompletionQueue.solve(kp, idx) &&
		kextFuncs.IONVMeController.CommandTimeout.solve(kp, idx);
	if (!solved || !validateDiagnosticABI(imageAddress, imageSize))
		return false;

	uint32_t installed = 0;
	if (!kextFuncs.IONVMeController.SubmitCommand.route(kp, idx, submitCommandWrapper))
		return false;
	installed |= HookSubmitCommand;
	atomic_store_explicit(&diagnosticHookMask, installed, memory_order_relaxed);

	if (!kextFuncs.IONVMeController.FilterInterruptRequest.route(kp, idx,
			filterInterruptRequestWrapper))
		return false;
	installed |= HookFilterInterruptRequest;
	atomic_store_explicit(&diagnosticHookMask, installed, memory_order_relaxed);

	if (!kextFuncs.IONVMeController.HandleInterruptRequest.route(kp, idx,
			handleInterruptRequestWrapper))
		return false;
	installed |= HookHandleInterruptRequest;
	atomic_store_explicit(&diagnosticHookMask, installed, memory_order_relaxed);

	if (!kextFuncs.IONVMeController.ProcessCompletionQueue.route(kp, idx,
			processCompletionQueueWrapper))
		return false;
	installed |= HookProcessCompletionQueue;
	atomic_store_explicit(&diagnosticHookMask, installed, memory_order_relaxed);

	// Install the essential timeout route last. Earlier wrappers remain transparent if this fails.
	if (!kextFuncs.IONVMeController.CommandTimeout.route(kp, idx, commandTimeoutWrapper))
		return false;
	installed |= HookCommandTimeout;
	atomic_store_explicit(&diagnosticHookMask, installed, memory_order_release);
	return true;
}

bool NVMeFixPlugin::solveSymbols(KernelPatcher& kp) {
	auto idx = plugin.kextInfo.loadIndex;
	bool res = true;
	res &= (kextFuncs.IONVMeController.IssueIdentifyCommandNew.solve(kp, idx) ||
			kextFuncs.IONVMeController.IssueIdentifyCommand.solve(kp, idx)) &&
	kextFuncs.IONVMeController.ProcessSyncNVMeRequest.solve(kp, idx) &&
	(kextFuncs.IONVMeController.GetRequestNew.solve(kp, idx) ||
	 kextFuncs.IONVMeController.GetRequest.solve(kp, idx)) &&
	kextFuncs.AppleNVMeRequest.BuildCommandGetFeatures.solve(kp, idx) &&
	kextFuncs.AppleNVMeRequest.BuildCommandSetFeaturesCommon.solve(kp, idx) &&
	kextFuncs.IONVMeController.ReturnRequest.solve(kp, idx) &&
	kextFuncs.AppleNVMeRequest.GetStatus.solve(kp, idx) &&
	kextFuncs.AppleNVMeRequest.GetOpcode.solve(kp, idx) &&
	kextFuncs.AppleNVMeRequest.GenerateIOVMSegments.solve(kp, idx) &&
	kextFuncs.IONVMeController.FilterInterruptRequest.solve(kp, idx);

	/* mov eax, [rdi+0xA8] */
	res &= kextMembers.AppleNVMeRequest.result.fromFunc(kextFuncs.AppleNVMeRequest.GetStatus.fptr,
														 0x8b, 0, 7, 4) &&
	/* movzx eax, byte ptr [rdi+0x10A] */
		kextMembers.AppleNVMeRequest.command.fromFunc(kextFuncs.AppleNVMeRequest.GetOpcode.fptr,
												  0xf, 0, 7) &&
	/* mov [r14+0xC0], r15 (14.0+) or mov [rbx+0xC0], r15 (11.3-13.x) or mov [rbx+0xC0], r12 (<=11.2) */
		(kextFuncs.IONVMeController.IssueIdentifyCommandNew.fptr ?
		kextMembers.AppleNVMeRequest.prpDescriptor.fromFunc(kextFuncs.IONVMeController.IssueIdentifyCommandNew.fptr, 0x89, 7, getKernelVersion() >= KernelVersion::Sonoma ? 14 : 3) :
		 kextMembers.AppleNVMeRequest.prpDescriptor.fromFunc(kextFuncs.IONVMeController.IssueIdentifyCommand.fptr, 0x89, 4, 3));

	/* cmp byte ptr [rdi+269h], 0 */
	kextMembers.IONVMeController.ANS2MSIWorkaround.fromFunc(kextFuncs.IONVMeController.FilterInterruptRequest.fptr,
																0x80, 7, 7, 0, 32);

	if (res)
		kextMembers.AppleNVMeRequest.controller.offs = kextMembers.AppleNVMeRequest.result.offs - 12;

	res &= PM.solveSymbols(kp);
	if (!res)
		DBGLOG(Log::Plugin, "Failed to solve symbols");
	return res;
}

void NVMeFixPlugin::submitCommandWrapper(void* controller, void* submissionQueue, void* request) {
	auto& plugin = globalPlugin();
	if (atomic_load_explicit(&plugin.armedController, memory_order_acquire) ==
		reinterpret_cast<uintptr_t>(controller)) {
		atomic_fetch_add_explicit(&plugin.submissions, 1, memory_order_relaxed);
		atomic_store_explicit(&plugin.lastSubmitTime, mach_absolute_time(), memory_order_relaxed);

		if (request && plugin.kextMembers.AppleNVMeRequest.command.has()) {
			const auto opcode = plugin.kextMembers.AppleNVMeRequest.command.get(request).common.opcode;
			if (opcode == NVMe::nvme_cmd_read)
				atomic_fetch_add_explicit(&plugin.readSubmissions, 1, memory_order_relaxed);
			else if (opcode == NVMe::nvme_cmd_write)
				atomic_fetch_add_explicit(&plugin.writeSubmissions, 1, memory_order_relaxed);
			else if (opcode == NVMe::nvme_cmd_flush)
				atomic_fetch_add_explicit(&plugin.flushSubmissions, 1, memory_order_relaxed);
		}
	}

	plugin.kextFuncs.IONVMeController.SubmitCommand(controller, submissionQueue, request);
}

bool NVMeFixPlugin::filterInterruptRequestWrapper(void* controller, void* source) {
	auto& plugin = globalPlugin();
	const bool target = atomic_load_explicit(&plugin.armedController, memory_order_acquire) ==
		reinterpret_cast<uintptr_t>(controller);
	if (target) {
		atomic_fetch_add_explicit(&plugin.filterCalls, 1, memory_order_relaxed);
		atomic_store_explicit(&plugin.lastFilterTime, mach_absolute_time(), memory_order_relaxed);
	}

	const bool accepted = plugin.kextFuncs.IONVMeController.FilterInterruptRequest(controller, source);
	if (target && accepted)
		atomic_fetch_add_explicit(&plugin.filterAccepted, 1, memory_order_relaxed);
	return accepted;
}

void NVMeFixPlugin::handleInterruptRequestWrapper(void* controller, void* source, int count) {
	auto& plugin = globalPlugin();
	if (atomic_load_explicit(&plugin.armedController, memory_order_acquire) ==
		reinterpret_cast<uintptr_t>(controller)) {
		atomic_fetch_add_explicit(&plugin.handlerCalls, 1, memory_order_relaxed);
		atomic_store_explicit(&plugin.lastHandlerTime, mach_absolute_time(), memory_order_relaxed);
	}

	plugin.kextFuncs.IONVMeController.HandleInterruptRequest(controller, source, count);
}

bool NVMeFixPlugin::processCompletionQueueWrapper(void* controller, void* completionQueue) {
	auto& plugin = globalPlugin();
	const bool target = atomic_load_explicit(&plugin.armedController, memory_order_acquire) ==
		reinterpret_cast<uintptr_t>(controller);
	if (target) {
		atomic_fetch_add_explicit(&plugin.completionQueueCalls, 1, memory_order_relaxed);
		atomic_store_explicit(&plugin.lastCompletionQueueTime, mach_absolute_time(),
			memory_order_relaxed);
	}

	const bool didWork = plugin.kextFuncs.IONVMeController.ProcessCompletionQueue(controller,
		completionQueue);
	if (target && didWork)
		atomic_fetch_add_explicit(&plugin.completionQueueWork, 1, memory_order_relaxed);
	return didWork;
}

void NVMeFixPlugin::commandTimeoutWrapper(void* controller, void* request) {
	auto& plugin = globalPlugin();
	if (atomic_load_explicit(&plugin.armedController, memory_order_acquire) ==
		reinterpret_cast<uintptr_t>(controller)) {
		atomic_fetch_add_explicit(&plugin.commandTimeouts, 1, memory_order_relaxed);
		atomic_store_explicit(&plugin.lastCommandTimeoutTime, mach_absolute_time(),
			memory_order_relaxed);
		plugin.persistDiagnosticSnapshot(SnapshotMode::CommandTimeout, request);
	}

	plugin.kextFuncs.IONVMeController.CommandTimeout(controller, request);
}

/**
 * This handler will be invoked when a media (whole disk or a partition) BSD node becomes registered.
 * We need to do two things now:
 * 1. Discover any undetected NVMe controllers.
 * 2. Try and solve symbols. If the relevant partition for symbol solving is not available, the call
 * will fail and we may succeed at next mount.
 * If we have all the symbols ready, we can proceed working with controllers.
 */
bool NVMeFixPlugin::matchingNotificationHandler(void* that, void* , IOService* service,
												IONotifier* notifier) {
	auto plugin = static_cast<NVMeFixPlugin*>(that);
	assert(plugin);
	assert(service);

	IOLockLock(plugin->lck);

	DBGLOG("nvmef", "matchingNotificationHandler for %s", service->getName());

	auto parent = service->getProvider();

	/* Typical depth is 9 on real setups */
	for (int i = 0; parent && i < controllerSearchDepth; i++) {
//		DBGLOG("nvmef", "Parent %s", parent->getName());

		if (parent->metaCast("IONVMeController")) {
			bool has = false;

			for (size_t i = 0; i < plugin->controllers.size(); i++)
				if (plugin->controllers[i]->controller == parent) {
					has = true;
					break;
				}

			if (!has) {
				auto entry = new ControllerEntry(parent);
				if (!entry) {
					SYSLOG(Log::Plugin, "Failed to allocate ControllerEntry memory");
					break;
				}
				if (!plugin->controllers.push_back(entry)) {
					SYSLOG(Log::Plugin, "Failed to insert ControllerEntry memory");
					ControllerEntry::deleter(entry);
					break;
				}
				break;
			}
		}

		parent = parent->getProvider();
	}

//	DBGLOG("nvmef", "Discovered %u controllers", plugin->controllers.size());

	IOLockUnlock(plugin->lck);

	if (atomic_load_explicit(&plugin->solvedSymbols, memory_order_acquire))
		plugin->handleControllers();

	return true;
}

void NVMeFixPlugin::handleControllers() {
	DBGLOG("nvmef", "handleControllers for %u controllers", controllers.size());
	for (size_t i = 0; i < controllers.size(); i++) {
		IOLockLock(controllers[i]->lck);
		controllers[i]->controller->retain();
		handleController(*controllers[i]);
		controllers[i]->controller->release();
		IOLockUnlock(controllers[i]->lck);
	}
}

void NVMeFixPlugin::forceEnableASPM(IOService *device) {
	IOPCIDevice *pci = static_cast<IOPCIDevice *>(device->metaCast("IOPCIDevice"));
	if (!pci) return;

	uint32_t aspm = 0;
	auto prop = device->getProperty("pci-aspm-default");
	if (prop) {
		auto num = OSDynamicCast(OSNumber, prop);
		if (num != nullptr) {
			aspm = num->unsigned32BitValue();
		} else {
			auto data = OSDynamicCast(OSData, prop);
			if (data != nullptr && data->getLength() == sizeof(aspm))
				lilu_os_memcpy(&aspm, data->getBytesNoCopy(), sizeof(aspm));
		}
	}

	DBGLOG(Log::Plugin, "Activating ASPM on %s, currently %X", safeString(device->getName()), aspm);

	// Do not repeat what is already done.
	if ((aspm & ASPM_Mask) == ASPM_L1EntryEnabled) return;

	UInt8 offset = 0;
	if (!pci->findPCICapability(kIOPCICapabilityIDPCIExpress, &offset)) {
		SYSLOG(Log::Plugin, "NO PCIe capability support on %s", safeString(device->getName()));
		return;
	}

	offset += 0x10; // link control offset.

	IOPCIAddressSpace space = pci->space;
	space.es.registerNumExtended = 0;

	auto linkControl = pci->configRead16(space, offset);
	pci->configWrite16(space, offset, (linkControl & ~ASPM_Mask) | ASPM_L1EntryEnabled);
	auto newLinkControl = pci->configRead16(space, offset);
	DBGLOG(Log::Plugin, "ASPM transition on %s from %X to %X", safeString(device->getName()), linkControl, newLinkControl);
	pci->setProperty("pci-aspm-custom", newLinkControl, 32);
}

bool NVMeFixPlugin::copyTrimmedIdentifyField(char* destination, size_t destinationSize,
											 const char* source, size_t sourceSize) {
	if (!destination || destinationSize == 0 || !source)
		return false;

	size_t begin = 0;
	while (begin < sourceSize && source[begin] == ' ')
		begin++;

	size_t end = sourceSize;
	while (end > begin && (source[end - 1] == ' ' || source[end - 1] == '\0'))
		end--;

	const size_t length = end - begin;
	if (length >= destinationSize)
		return false;
	for (size_t i = begin; i < end; i++)
		if (source[i] == '\0')
			return false;

	if (length > 0)
		lilu_os_memcpy(destination, source + begin, length);
	destination[length] = '\0';
	return true;
}

bool NVMeFixPlugin::prepareDiagnosticStorage() {
	unsigned expected = DiagnosticStorageUninitialised;
	if (!atomic_compare_exchange_strong_explicit(&storageState, &expected,
			DiagnosticStorageInitialising, memory_order_acq_rel, memory_order_acquire))
		return expected == DiagnosticStorageReady;

	if (!diagnosticStorage.init()) {
		diagnosticStorage.deinit();
		atomic_store_explicit(&storageState, DiagnosticStorageUninitialised,
			memory_order_release);
		return false;
	}

	if (diagnosticStorage.exists(PM981aDiagnosticKey)) {
		diagnosticStorage.deinit();
		atomic_store_explicit(&storageState, DiagnosticStorageOccupied, memory_order_release);
		return false;
	}

	atomic_store_explicit(&storageState, DiagnosticStorageReady, memory_order_release);
	return true;
}

uint32_t NVMeFixPlugin::diagnosticCRC32(const uint8_t* data, size_t size) {
	uint32_t crc = 0xFFFFFFFFU;
	for (size_t i = 0; i < size; i++) {
		crc ^= data[i];
		for (unsigned bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
	}
	return ~crc;
}

void NVMeFixPlugin::persistDiagnosticSnapshot(SnapshotMode mode, void* request) {
	if (atomic_load_explicit(&storageState, memory_order_acquire) != DiagnosticStorageReady)
		return;

	bool expected = false;
	if (!atomic_compare_exchange_strong_explicit(&nvramWriteAttempted, &expected, true,
			memory_order_acq_rel, memory_order_relaxed))
		return;

	DiagnosticSnapshot snapshot {};
	snapshot.magic = PM981aSnapshotMagic;
	snapshot.schemaVersion = PM981aSnapshotVersion;
	snapshot.size = sizeof(snapshot);
	snapshot.mode = static_cast<uint8_t>(mode);
	// A present snapshot proves write success. Sync is attempted afterwards and cannot be
	// represented without replacing the just-written one-shot snapshot.
	snapshot.writeOutcome = static_cast<uint8_t>(SnapshotOutcome::SucceededIfPresent);
	snapshot.syncOutcome = static_cast<uint8_t>(SnapshotOutcome::AttemptedResultNotPersisted);
	snapshot.flags = SnapshotExactImage | SnapshotExactTarget | SnapshotStorageReady |
		SnapshotExistingKeyAbsent;
	snapshot.hookMask = atomic_load_explicit(&diagnosticHookMask, memory_order_acquire);
	lilu_os_memcpy(snapshot.ionvmeUUID, PM981aIONVMeUUID, sizeof(snapshot.ionvmeUUID));
	snapshot.pciVendor = PM981aVendor;
	snapshot.pciDevice = PM981aDevice;
	lilu_os_memcpy(snapshot.model, PM981aModel, sizeof(PM981aModel));
	lilu_os_memcpy(snapshot.firmware, PM981aFirmware, sizeof(PM981aFirmware));
	if (mode == SnapshotMode::CommandTimeout && request &&
		kextMembers.AppleNVMeRequest.command.has()) {
		auto& command = kextMembers.AppleNVMeRequest.command.get(request).common;
		snapshot.opcode = command.opcode;
		snapshot.commandID = command.command_id;
		snapshot.namespaceID = command.nsid;
	}
	snapshot.submissions = atomic_load_explicit(&submissions, memory_order_relaxed);
	snapshot.readSubmissions = atomic_load_explicit(&readSubmissions, memory_order_relaxed);
	snapshot.writeSubmissions = atomic_load_explicit(&writeSubmissions, memory_order_relaxed);
	snapshot.flushSubmissions = atomic_load_explicit(&flushSubmissions, memory_order_relaxed);
	snapshot.filterCalls = atomic_load_explicit(&filterCalls, memory_order_relaxed);
	snapshot.filterAccepted = atomic_load_explicit(&filterAccepted, memory_order_relaxed);
	snapshot.handlerCalls = atomic_load_explicit(&handlerCalls, memory_order_relaxed);
	snapshot.completionQueueCalls = atomic_load_explicit(&completionQueueCalls,
		memory_order_relaxed);
	snapshot.completionQueueWork = atomic_load_explicit(&completionQueueWork,
		memory_order_relaxed);
	snapshot.commandTimeouts = atomic_load_explicit(&commandTimeouts, memory_order_relaxed);
	snapshot.lastSubmitTime = atomic_load_explicit(&lastSubmitTime, memory_order_relaxed);
	snapshot.lastFilterTime = atomic_load_explicit(&lastFilterTime, memory_order_relaxed);
	snapshot.lastHandlerTime = atomic_load_explicit(&lastHandlerTime, memory_order_relaxed);
	snapshot.lastCompletionQueueTime = atomic_load_explicit(&lastCompletionQueueTime,
		memory_order_relaxed);
	snapshot.lastCommandTimeoutTime = atomic_load_explicit(&lastCommandTimeoutTime,
		memory_order_relaxed);
	snapshot.crc32 = 0;
	snapshot.crc32 = diagnosticCRC32(reinterpret_cast<const uint8_t*>(&snapshot),
		sizeof(snapshot));

	if (diagnosticStorage.write(PM981aDiagnosticKey,
			reinterpret_cast<const uint8_t*>(&snapshot), sizeof(snapshot), NVStorage::OptRaw))
		diagnosticStorage.sync();
}

bool NVMeFixPlugin::controllerIsTerminating(uintptr_t controller) {
	if (atomic_load_explicit(&terminatedControllerOverflow, memory_order_acquire))
		return true;
	for (size_t i = 0; i < terminatedControllerSlots; i++)
		if (atomic_load_explicit(&terminatedControllers[i], memory_order_acquire) == controller)
			return true;
	return false;
}

void NVMeFixPlugin::recordTerminatingController(uintptr_t controller) {
	for (size_t i = 0; i < terminatedControllerSlots; i++) {
		uintptr_t current = atomic_load_explicit(&terminatedControllers[i], memory_order_acquire);
		if (current == controller)
			return;
		if (current == 0) {
			if (atomic_compare_exchange_strong_explicit(&terminatedControllers[i], &current,
					controller, memory_order_release, memory_order_relaxed) || current == controller)
				return;
		}
	}
	// A full tombstone set fails closed for future publication instead of permitting late arming.
	atomic_store_explicit(&terminatedControllerOverflow, true, memory_order_release);
}

void NVMeFixPlugin::handlePM981aDiagnostics(ControllerEntry& entry,
											const NVMe::nvme_id_ctrl* identifyController) {
	if ((!persistenceTestRequested && !runtimeDiagnosticsRequested) ||
		!atomic_load_explicit(&diagnosticImageValid, memory_order_acquire))
		return;

	uint32_t vendor = 0;
	uint32_t device = 0;
	propertyFromParent(entry.controller, "vendor-id", vendor);
	propertyFromParent(entry.controller, "device-id", device);
	if (vendor != PM981aVendor || device != PM981aDevice ||
		identifyController->vid != PM981aVendor)
		return;

	char model[41] {};
	char firmware[9] {};
	if (!copyTrimmedIdentifyField(model, sizeof(model), identifyController->mn,
			sizeof(identifyController->mn)) ||
		!copyTrimmedIdentifyField(firmware, sizeof(firmware), identifyController->fr,
			sizeof(identifyController->fr)) ||
		strcmp(model, PM981aModel) != 0 || strcmp(firmware, PM981aFirmware) != 0)
		return;

	// Never arm a timeout route unless a custom variable can be written in normal context.
	// A transient early failure remains retryable through a later controller notification.
	if (!prepareDiagnosticStorage())
		return;

	const uintptr_t controller = reinterpret_cast<uintptr_t>(entry.controller);
	if (runtimeDiagnosticsRequested &&
		atomic_load_explicit(&diagnosticRoutesReady, memory_order_acquire) &&
		!controllerIsTerminating(controller)) {
		uintptr_t expected = 0;
		atomic_compare_exchange_strong_explicit(&armedController, &expected, controller,
			memory_order_release, memory_order_relaxed);

		// Close the race where termination observes an empty target immediately before publication.
		if (controllerIsTerminating(controller)) {
			expected = controller;
			atomic_compare_exchange_strong_explicit(&armedController, &expected, 0,
				memory_order_release, memory_order_relaxed);
		}
	}

	if (persistenceTestRequested)
		persistDiagnosticSnapshot(SnapshotMode::PersistenceTest);
}

void NVMeFixPlugin::handleController(ControllerEntry& entry) {
	assert(entry.controller);

	if (entry.processed) {
		// A later normal-context notification may retry only transient diagnostic storage setup.
		if (entry.identify && (persistenceTestRequested || runtimeDiagnosticsRequested)) {
			auto identifyController = reinterpret_cast<NVMe::nvme_id_ctrl*>(
				entry.identify->getBytesNoCopy());
			if (identifyController)
				handlePM981aDiagnostics(entry, identifyController);
		}
		return;
	}

	/* No error signaling -- just ACK the discovery to notification handler */
	entry.processed = true;

	uint32_t vendor {};
	propertyFromParent(entry.controller, "vendor-id", vendor);
	if (vendor == 0x106b || entry.controller->metaCast("AppleNVMeController")) {
		SYSLOG(Log::Plugin, "Ignoring Apple controller");
		return;
	}

	/**
	 * Force enable ASPM when the user cannot provide device properties.
	 */
	if (checkKernelArgument("-nvmefaspm")) {
		auto ssd = OSDynamicCast(IOService, entry.controller->getParentEntry(gIOServicePlane));
		if (ssd) {
			forceEnableASPM(ssd);
			auto bridge = OSDynamicCast(IOService, ssd->getParentEntry(gIODTPlane));
			if (bridge)
				forceEnableASPM(bridge);
		}
	}

	/**
	 * Force enable ANS2MSIWorkaround.
	 *
	 * We would often get a panic with I/O Read command timeout on VMware and Samsung PM981.
	 * Some investigation showed that CQ head entry phase and CQ phase would mismatch.
	 * This implies there is a race such that CQ head gets updated to point to an entry with inverted
	 * phase.
	 * Since FilterIRQ detects phase mismatch, it does not schedule HandleIRQ at the workloop of NVMe
	 * controller, so a request is never handled and we get a timeout. If Filter and Handle IRQ calls can
	 * possibly race, this may happen because HandleIRQ does not manage to update CQ phase in time before
	 * FilterIRQ phase check is scheduled, observing the old phase. This is the case in situation where
	 * two FilterIRQ calls happen with no HandleIRQ in between where the controller was too slow to
	 * notice INTMS being set.
	 * Normally, IRQ is masked just before HandleIRQ is scheduled in FilterIRQ, and unmasked when
	 * HandleIRQ is done. IONVMeController::ANS2MSIWorkaround forces IRQ to be masked at the very
	 * start of FilterIRQ instead so that FilterIRQ does not race with itself. This seems to eliminate
	 * the timeouts.
	 **/
	if (kextMembers.IONVMeController.ANS2MSIWorkaround.has()) {
		kextMembers.IONVMeController.ANS2MSIWorkaround.get(entry.controller) = 1;
	} else {
		DBGLOG(Log::Plugin, "Ignoring ANS2 workaround patch on newer system");
	}

	/* First get quirks based on PCI device */
	entry.quirks = NVMe::quirksForController(entry.controller);
	propertyFromParent(entry.controller, "ps-max-latency-us", entry.ps_max_latency_us);

	IOBufferMemoryDescriptor* identifyDesc {nullptr};

	if (identify(entry, identifyDesc) != kIOReturnSuccess || !identifyDesc) {
		SYSLOG(Log::Plugin, "Failed to identify controller");
		return;
	}

	auto ctrl = reinterpret_cast<NVMe::nvme_id_ctrl*>(identifyDesc->getBytesNoCopy());
	if (!ctrl) {
		DBGLOG(Log::Plugin, "Failed to get identify buffer bytes");
		if (identifyDesc)
			identifyDesc->release();
		return;
	}

	entry.identify = identifyDesc;

	/* Get additional quirks based on identify data */
	entry.quirks |= NVMe::quirksForController(ctrl->vid, ctrl->mn, ctrl->fr);

	entry.controller->setProperty("quirks", OSNumber::withNumber(entry.quirks, 8 * sizeof(entry.quirks)));

#ifdef DEBUG
	char mn[40];
	lilu_os_memcpy(mn, ctrl->mn, sizeof(mn));
	mn[sizeof(mn) - 1] = '\0';

	DBGLOG(Log::Plugin, "Identified model %s (vid 0x%x)", mn, ctrl->vid);
#endif

	if (!enableAPST(entry, ctrl))
		SYSLOG(Log::APST, "Failed to enable APST");

	if (!PM.init(entry, ctrl, entry.apste))
		SYSLOG(Log::PM, "Failed to initialise power management");

	handlePM981aDiagnostics(entry, ctrl);
}

IOReturn NVMeFixPlugin::identify(ControllerEntry& entry, IOBufferMemoryDescriptor*& desc) {
	IOReturn ret = kIOReturnSuccess;

	uint8_t* data {nullptr};
	bool prepared {false};

	desc = IOBufferMemoryDescriptor::withCapacity(sizeof(NVMe::nvme_id_ctrl), kIODirectionIn);

	if (!desc) {
		SYSLOG(Log::Plugin, "Failed to init descriptor");
		ret = kIOReturnNoResources;
		goto fail;
	}
	data = static_cast<uint8_t*>(desc->getBytesNoCopy());
	memset(data, '\0', desc->getLength());

	ret = desc->prepare();
	if (ret != kIOReturnSuccess) {
		SYSLOG(Log::Plugin, "Failed to prepare descriptor");
		goto fail;
	}
	prepared = true;

	if (kextFuncs.IONVMeController.IssueIdentifyCommandNew.fptr)
		ret = kextFuncs.IONVMeController.IssueIdentifyCommandNew(entry.controller, desc, 0, false);
	else
		ret = kextFuncs.IONVMeController.IssueIdentifyCommand(entry.controller, desc, nullptr, 0);
	if (ret != kIOReturnSuccess) {
		SYSLOG(Log::Plugin, "issueIdentifyCommand failed");
		goto fail;
	}

fail:
	if (prepared)
		desc->complete();
	if (ret != kIOReturnSuccess && desc)
		desc->release();
	return ret;
}

IOReturn NVMeFixPlugin::NVMeFeatures(ControllerEntry& entry, unsigned fid, unsigned* dword11,
										IOBufferMemoryDescriptor* desc, uint32_t* res, bool set) {
	auto ret = kIOReturnSuccess;

	bool prepared {false};

	if (desc) {
		ret = desc->prepare();
		prepared = ret == kIOReturnSuccess;
	}

	if (!desc || prepared) {
		void *req;
		if (kextFuncs.IONVMeController.GetRequestNew.fptr)
			req = kextFuncs.IONVMeController.GetRequestNew(entry.controller, 1, 0); /* Set 0b10 to tickle */
		else
			req = kextFuncs.IONVMeController.GetRequest(entry.controller, 1); /* Set 0b10 to tickle */

		if (!req) {
			DBGLOG(Log::Feature, "IONVMeController::GetRequest failed");
			ret = kIOReturnNoResources;
		} else if (desc)
			ret = reinterpret_cast<IODMACommand*>(req)->setMemoryDescriptor(desc);

		if (ret == kIOReturnSuccess) {
			if (set)
				kextFuncs.AppleNVMeRequest.BuildCommandSetFeaturesCommon(req, fid);
			else
				kextFuncs.AppleNVMeRequest.BuildCommandGetFeatures(req, fid);

			if (dword11)
				kextMembers.AppleNVMeRequest.command.get(req).features.dword11 = *dword11;
			if (desc) {
				kextMembers.AppleNVMeRequest.prpDescriptor.get(req) = desc;
				ret = reinterpret_cast<IODMACommand*>(req)->prepare(0, desc->getLength());
			}

			if (ret != kIOReturnSuccess)
				DBGLOG(Log::Feature, "Failed to prepare DMA command");
			else {
				if (desc)
					ret = kextFuncs.AppleNVMeRequest.GenerateIOVMSegments(req, 0,
																		  desc->getLength());

				if (ret != kIOReturnSuccess)
					DBGLOG(Log::Feature, "Failed to generate IO VM segments");
				else {
					kextMembers.AppleNVMeRequest.controller.get(req) = entry.controller;

					ret = kextFuncs.IONVMeController.ProcessSyncNVMeRequest(entry.controller,
																			req);
					if (ret != kIOReturnSuccess)
						DBGLOG(Log::Feature, "ProcessSyncNVMeRequest failed");
					else if (res)
						*res = kextMembers.AppleNVMeRequest.result.get(req);
				}
			}
			if (desc)
				reinterpret_cast<IODMACommand*>(req)->complete();
			kextFuncs.IONVMeController.ReturnRequest(entry.controller, req);
		}
	} else
		SYSLOG(Log::Feature, "Failed to prepare buffer");

	if (desc && prepared)
		desc->complete();

	return ret;
}

/* Notifications are serialized for a single controller, so we don't have to sync with removal */
bool NVMeFixPlugin::terminatedNotificationHandler(void* that, void* , IOService* service,
												IONotifier* notifier) {
	auto plugin = static_cast<NVMeFixPlugin*>(that);
	assert(plugin);
	assert(service && service->metaCast("IONVMeController"));

	/* Controller retain count should equal 0, so we don't need to hold its lock now */
	IOLockLock(plugin->lck);
	for (size_t i = 0; i < plugin->controllers.size(); i++)
		if (plugin->controllers[i]->controller == service) {
			const uintptr_t controller = reinterpret_cast<uintptr_t>(service);
			plugin->recordTerminatingController(controller);
			uintptr_t expected = controller;
			atomic_compare_exchange_strong_explicit(&plugin->armedController, &expected, 0,
				memory_order_release, memory_order_relaxed);
			plugin->controllers.erase(i);
			break;
	   }
	IOLockUnlock(plugin->lck);

	return false;
}

/**
 * NOTE: We are in kmod context, not IOService. This works fine as long as we publish our personality
 * in Info.plist to match something in ioreg, but specify a non-existing IOClass so that IOKit attempts
 * to load us anyway. It is otherwise unsafe to use matching notifications from kmod when we have a
 * living IOService.
 */
void NVMeFixPlugin::init() {
	LiluAPI::Error err;

	persistenceTestRequested = checkKernelArgument("-nvmefpm981anvtest");
	runtimeDiagnosticsRequested = checkKernelArgument("-nvmefpm981adiag");
	if (persistenceTestRequested && runtimeDiagnosticsRequested) {
		persistenceTestRequested = false;
		runtimeDiagnosticsRequested = false;
	}

	if (!(lck = IOLockAlloc())) {
		SYSLOG(Log::Plugin, "Failed to alloc lock");
		goto fail;
	}

	atomic_store_explicit(&solvedSymbols, false, memory_order_relaxed);

	matchingNotifier = IOService::addMatchingNotification(gIOPublishNotification,
							IOService::serviceMatching("IOMediaBSDClient"),
							matchingNotificationHandler,
						    this);
	if (!matchingNotifier) {
		SYSLOG(Log::Plugin, "Failed to register for matching notification");
		goto fail;
	}

	terminationNotifier = IOService::addMatchingNotification(gIOTerminatedNotification,
							IOService::serviceMatching("IONVMeController"),
							terminatedNotificationHandler,
						    this);
	if (!terminationNotifier) {
		SYSLOG(Log::Plugin, "Failed to register for termination notification");
		goto fail;
	}

	DBGLOG(Log::Plugin, "Registered for matching notifications");

	err = lilu.onKextLoad(&kextInfo, 1, NVMeFixPlugin::processKext, this);
	if (err != LiluAPI::Error::NoError) {
		SYSLOG(Log::Plugin, "Failed to register kext load cb");
		goto fail;
	}

	return;
fail:
	if (lck)
		IOLockFree(lck);
	if (matchingNotifier)
		matchingNotifier->remove();
	if (terminationNotifier)
		terminationNotifier->remove();
}

void NVMeFixPlugin::deinit() {
	/* This kext is not unloadable */
	panic("nvmef: deinit called");
}

NVMeFixPlugin::ControllerEntry* NVMeFixPlugin::entryForController(IOService* controller) const {
	for (size_t i = 0; i < controllers.size(); i++)
		if (controllers[i]->controller == controller)
			return controllers[i];
	return nullptr;
}

static const char *bootargOff[] {
	"-nvmefoff"
};

static const char *bootargDebug[] {
	"-nvmefdbg"
};

PluginConfiguration ADDPR(config) {
	xStringify(PRODUCT_NAME),
	parseModuleVersion(xStringify(MODULE_VERSION)),
	LiluAPI::AllowNormal | LiluAPI::AllowInstallerRecovery,
	bootargOff,
	arrsize(bootargOff),
	bootargDebug,
	arrsize(bootargDebug),
	nullptr,
	0,
	KernelVersion::Mojave,
	KernelVersion::Tahoe,
	[]() {
		NVMeFixPlugin::globalPlugin().init();
	}
};
