#include "memory.h"

// USERMODE FUNCTIONS


bool memory::user::read_memory(HANDLE pID, PVOID address, PVOID buffer, SIZE_T size)
{
	PEPROCESS proc;
	if (PsLookupProcessByProcessId(pID, &proc) != STATUS_SUCCESS) return false;


	size_t bytes = 0;
	MmCopyVirtualMemory(proc, address, IoGetCurrentProcess(), buffer, size, KernelMode, &bytes);
	return true;
	

	/*
	PEPROCESS pProcess = NULL;
	if (pID == 0) return false;

	NTSTATUS NtRet = PsLookupProcessByProcessId(pID, &pProcess);
	if (NtRet != STATUS_SUCCESS) return false;

	ULONG_PTR process_dirbase = physical::GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{

		uint64_t CurPhysAddr = physical::TranslateLinearAddress(process_dirbase, (ULONG64)address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		NtRet = physical::ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)buffer + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesRead == 0) break;
	}

	return true;

	*/
}

bool memory::user::write_memory(HANDLE pID, PVOID address, PVOID buffer, SIZE_T size)
{
	PEPROCESS proc;
	if (PsLookupProcessByProcessId(pID, &proc) != STATUS_SUCCESS) return false;


	size_t bytes = 0;
	NTSTATUS status = MmCopyVirtualMemory(IoGetCurrentProcess(), buffer, proc, address, size, KernelMode, &bytes);
	if (status != STATUS_SUCCESS)
	{
		print("status write fail: ", status);
		return false;
	}
	return true;
	/*
	PEPROCESS pProcess = NULL;
	if (pID == 0) return false;

	NTSTATUS NtRet = PsLookupProcessByProcessId(pID, &pProcess);
	if (NtRet != STATUS_SUCCESS) return false;

	ULONG_PTR process_dirbase = physical::GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = physical::TranslateLinearAddress(process_dirbase, (ULONG64)address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		NtRet = physical::WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)buffer + CurOffset), WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesWritten == 0) break;
	}

	return true;
	*/
}

HANDLE memory::user::GetProcID(const char* process_name)
{
	ANSI_STRING AS = { 0 };
	UNICODE_STRING US = { 0 };	

	RtlInitAnsiString(&AS, process_name);
	RtlAnsiStringToUnicodeString(&US, &AS, true); // converting to the type used by the process ID in SYSTEM_PROCESS_INFO struct

	ULONG buffer_size = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &buffer_size);  // gets the size of the SYSTEM_PROCESS_INFO struct

	PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'PYXR'); // allocates pool memory to buffer
	if (!buffer)
	{
		print("Failed to allocate pool");
		return 0;
	}

	ZwQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, NULL); // returns pointer to SYSTEM_PROCESS_INFO


	PSYSTEM_PROCESS_INFO process_info = reinterpret_cast<PSYSTEM_PROCESS_INFO>(buffer);

	if (!process_info)
	{
		print("process_info is null lol get fucked");
		ExFreePoolWithTag(buffer, 'PYXR');
		return 0;
	}
	
	while (process_info->NextEntryOffset) // loops through all the processes
	{	
		if (!RtlCompareUnicodeString(&US, &process_info->ImageName, TRUE))
		{
			ExFreePoolWithTag(buffer, 'PYXR');
			return process_info->ProcessId;
		}
		
		process_info = (PSYSTEM_PROCESS_INFO)((BYTE*)process_info + process_info->NextEntryOffset); // sets it to the address of the next struct

	}

	RtlFreeUnicodeString(&US);
	RtlFreeAnsiString(&AS);
	ExFreePoolWithTag(buffer, 'PYXR');
	return 0;
}


PVOID memory::user::GetBaseAddress(HANDLE procID) // returns base address of process
{
	PEPROCESS proc = 0;

	if (NT_SUCCESS(PsLookupProcessByProcessId(procID, &proc))) 
		return PsGetProcessSectionBaseAddress(proc);

	return 0;
}

PVOID memory::user::GetPEB(HANDLE procID) // returns PEB of specified process
{
	PEPROCESS process = 0;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(procID, &process)))
		return 0;

	return (PVOID)PsGetProcessPeb(process);


}



// KERNELMODE FUNCTIONS


bool memory::kernel::write_memory_ro(void* address, void* buffer, size_t size) {

	PMDL mdl = IoAllocateMdl(address, static_cast<ULONG>(size), FALSE, FALSE, NULL); // allocates memory to MDL

	if (!mdl)
		return false;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); // locks the paged memory so that it cant be read while we are trying to write to it
	PVOID Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority); // maps the paged and returns pointer to mapped pages
	MmProtectMdlSystemAddress(mdl, PAGE_READWRITE); // allows the driver to read and write the memory of the pages whilst other drivers cannot

	RtlCopyMemory(address, buffer, size); // copys over the memory

    // freeing the restrictions we put on the memory

	MmUnmapLockedPages(Mapping, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return true;
}

#pragma region end

PVOID memory::kernel::get_driver_module_base(const char* module_name) 
{
	ULONG buffer = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, buffer, &buffer); // gets size of module list

	if (!buffer) {
		print("get_module_base() -> Failed to assert buffer");
		return 0;
	}

	PRTL_PROCESS_MODULES system_module_api = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, buffer); // allocates memory to PRTL_PROCESS_MODULES struct
	if (!system_module_api) {
		print("get_module_base() -> Failed to assert system_module_api");
		return 0;
	}

	RtlZeroMemory(system_module_api, buffer); // zeroes the memory of PRTL_PROCESS_MODULES

	status = ZwQuerySystemInformation(SystemModuleInformation, system_module_api, buffer, (PULONG)&buffer); // gets PRTL_PROCESS_MODULES
	if (!NT_SUCCESS(status)) {
		print("get_module_base() -> Failed to assert status ( 2 )");
		ExFreePool(system_module_api);
		return 0;
	}

	PVOID module_base = 0;

	PRTL_PROCESS_MODULE_INFORMATION module_list = system_module_api->Modules; // gets module list
	for (ULONG i = 0; i < system_module_api->NumberOfModules; i++) { 
		if (strcmp((char*)module_list[i].FullPathName, module_name) == 0) { // checks if the module is the on requested
			print("get_module_base() -> Found module %s", module_name);
			module_base = (PVOID)module_list[i].ImageBase;
			break;
		}
	}

	ExFreePool(system_module_api); // frees pool memory
	return module_base;
}

PVOID memory::kernel::find_pattern(PVOID memory, size_t size, const char* pattern, const char* mask) // scans through kernel memory looking for patterns
{
	size_t sig_length = strlen(mask); // finds length of sig
	if (sig_length > size) return nullptr;

	for (size_t i = 0; i < size - sig_length; i++) // loops through memory
	{
		bool found = true;
		for (size_t j = 0; j < sig_length; j++) // loops through memory and checks if each byte is correct
			found &= mask[j] == '?' || pattern[j] == *((char*)memory + i + j);

		if (found)
			return (char*)memory + i; // returns address if all memory is the same as the sig
	}
	return nullptr;
}

