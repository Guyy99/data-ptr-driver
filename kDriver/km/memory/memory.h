#pragma once

#include "phys.h"

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

#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

// extern undocumented ntapi functions


extern "C" PPEB PsGetProcessPeb(IN PEPROCESS Process);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

