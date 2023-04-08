#include "memory.h"

// USERMODE FUNCTIONS


bool memory::user::read_memory(HANDLE pID, PVOID address, PVOID buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	SIZE_T bytes = 0;
	PEPROCESS process = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pID, &process)))
	{
		print("process not found");
		return false;
	}

	return MmCopyVirtualMemory(process, address, PsGetCurrentProcess(), buffer, size, KernelMode, &bytes) == STATUS_SUCCESS;
}

bool memory::user::write_memory(HANDLE pID, PVOID address, PVOID buffer, SIZE_T size)
{
	if (!address || !buffer || !size)
		return false;

	SIZE_T bytes;
	PEPROCESS process = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pID, &process)))
	{
		print("process not found");
		return false;
	}

	NTSTATUS status = MmCopyVirtualMemory(PsGetCurrentProcess(), address, process, buffer, size, KernelMode, &bytes);

	print("status of copy: [%p]", status);

	return status == STATUS_SUCCESS;
}

HANDLE memory::user::GetProcID(const char* process_name)
{
	ANSI_STRING AS = { 0 };
	UNICODE_STRING US = { 0 };	

	RtlInitAnsiString(&AS, process_name);
	RtlAnsiStringToUnicodeString(&US, &AS, true);

	ULONG buffer_size = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &buffer_size);

	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'PYXR');
	if (!buffer)
	{
		print("Failed to allocate pool");
		return 0;
	}

	ZwQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, NULL);


	PSYSTEM_PROCESS_INFO process_info = reinterpret_cast<PSYSTEM_PROCESS_INFO>(buffer);

	if (!process_info)
	{
		print("process_info is null lol get fucked");
		ExFreePoolWithTag(buffer, 'PYXR');
		return 0;
	}
	
	while (process_info->NextEntryOffset)
	{	
		if (!RtlCompareUnicodeString(&US, &process_info->ImageName, TRUE))
		{
			ExFreePoolWithTag(buffer, 'PYXR');
			return process_info->ProcessId;
		}
		
		process_info = (PSYSTEM_PROCESS_INFO)((BYTE*)process_info + process_info->NextEntryOffset);

	}


	RtlFreeUnicodeString(&US);
	RtlFreeAnsiString(&AS);
	ExFreePoolWithTag(buffer, 'PYXR');
	return 0;


}


PVOID memory::user::GetBaseAddress(HANDLE procID)
{
	PEPROCESS proc = 0;

	if (NT_SUCCESS(PsLookupProcessByProcessId(procID, &proc)))
		return PsGetProcessSectionBaseAddress(proc);

	return 0;
}

PVOID memory::user::GetPEB(HANDLE procID)
{
	PEPROCESS process = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(procID, &process)))
		return 0;

	return (PVOID)PsGetProcessPeb(process);


}



// KERNELMODE FUNCTIONS


bool memory::kernel::write_memory_ro(void* address, void* buffer, size_t size) {
	PMDL mdl = IoAllocateMdl(address, static_cast<ULONG>(size), FALSE, FALSE, NULL);

	if (!mdl)
		return false;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

	RtlCopyMemory(address, buffer, size);

	MmUnmapLockedPages(Mapping, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return true;
}

#pragma region end

PVOID memory::kernel::get_driver_module_base(const char* module_name) 
{
	ULONG buffer = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, buffer, &buffer);

	if (!buffer) {
		print("get_module_base() -> Failed to assert buffer");
		return 0;
	}

	PRTL_PROCESS_MODULES system_module_api = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, buffer);
	if (!system_module_api) {
		print("get_module_base() -> Failed to assert system_module_api");
		return 0;
	}

	RtlZeroMemory(system_module_api, buffer);

	status = ZwQuerySystemInformation(SystemModuleInformation, system_module_api, buffer, (PULONG)&buffer);
	if (!NT_SUCCESS(status)) {
		print("get_module_base() -> Failed to assert status ( 2 )");
		ExFreePool(system_module_api);
		return 0;
	}

	PVOID module_base = 0;

	PRTL_PROCESS_MODULE_INFORMATION module_list = system_module_api->Modules;
	for (ULONG i = 0; i < system_module_api->NumberOfModules; i++) {
		if (strcmp((char*)module_list[i].FullPathName, module_name) == 0) {
			print("get_module_base() -> Found module %s", module_name);
			module_base = (PVOID)module_list[i].ImageBase;
			break;
		}
	}

	ExFreePool(system_module_api);
	return module_base;
}

PVOID memory::kernel::find_pattern(PVOID memory, size_t size, const char* pattern, const char* mask)
{
	size_t sig_length = strlen(mask);
	if (sig_length > size) return nullptr;

	for (size_t i = 0; i < size - sig_length; i++)
	{
		bool found = true;
		for (size_t j = 0; j < sig_length; j++)
			found &= mask[j] == '?' || pattern[j] == *((char*)memory + i + j);

		if (found)
			return (char*)memory + i;
	}
	return nullptr;
}

