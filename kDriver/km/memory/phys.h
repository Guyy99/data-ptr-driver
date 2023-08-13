#pragma once

#include "defs.h"

extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);

namespace memory::kernel::physical
{

	const DWORD GetUserDirectoryTableBaseOffset();
	const UINT64 GetProcessCr3(const PEPROCESS pProcess);

	const UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress);
	NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
	NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
	

	NTSTATUS ReadVirtual(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteVirtual(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* written);

	uint64_t VirtualAddressToPhysicalAddress(void* VirtualAddress);
	uint64_t PhysicalAddressToVirtualAddress(uint64_t PhysicalAddress);

	const UINT64 GetKernelDirBase();


}
