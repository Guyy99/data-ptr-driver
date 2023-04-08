#pragma once

#include "defs.h"

namespace memory
{
	namespace user
	{
		HANDLE GetProcID(const char* process_name);
		PVOID GetBaseAddress(HANDLE procID);
		PVOID GetPEB(HANDLE procID);
		bool read_memory(HANDLE pID, PVOID address, PVOID buffer, SIZE_T size);
		bool write_memory(HANDLE pID, PVOID address, PVOID buffer, SIZE_T size);
	}

	namespace kernel
	{
		bool write_memory_ro(void* address, void* buffer, size_t size);
		PVOID get_driver_module_base(const char* module_name);
		PVOID find_pattern(PVOID memory, size_t size, const char* pattern, const char* mask);
	}
}






extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);

extern "C" PPEB PsGetProcessPeb(IN PEPROCESS Process);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);


