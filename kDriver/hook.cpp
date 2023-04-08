#include "hook.h"
#include "includes.h"
#include "memory.h"
#include "defs.h"

typedef unsigned __int64 _QWORD;

typedef __int64(__fastcall* Qword_ptrOriginal)(_QWORD, _QWORD, _QWORD, _QWORD, DWORD, DWORD);
Qword_ptrOriginal func;


__int64 __fastcall HookFunction(_QWORD a1, _QWORD a2, _QWORD a3, _QWORD a4, DWORD a5, DWORD a6)
{
	print("hooked func called");

	if (!a3)
	{
		print("arg is null");
		return func(a1, a2, a3, a4, a5, a6);
	}

	READ_WRITE* instructions = (READ_WRITE*)a3;
	

	if (instructions->key != 0x69420)
		return func(a1, a2, a3, a4, a5, a6);
	
	if (instructions->request_PID)
	{
		instructions->PID = (uintptr_t)memory::user::GetProcID(instructions->processName);

		return 0;
	}
	else if (instructions->request_module_base)
	{
		instructions->moduleBase = (uintptr_t)memory::user::GetBaseAddress((HANDLE)instructions->PID);

		return 0;

	}
	else if (instructions->request_read)
	{
		print("address of buffer [%p]", instructions->pBuffer);
		memory::user::read_memory((HANDLE)instructions->PID, (PVOID)instructions->address, (PVOID)instructions->pBuffer, instructions->size_of_buffer);

		return 0;
	}
	else if (instructions->request_write)
	{
		instructions->operation_success = memory::user::write_memory((HANDLE)instructions->PID, (PVOID)instructions->address, (PVOID)instructions->pBuffer, instructions->size_of_buffer);

		return 0;
	}
	else if (instructions->request_PEB)
	{
		instructions->PEB = (uintptr_t)memory::user::GetPEB((HANDLE)instructions->PID);

		return 0;
	}

	return 0;
}



void hook::Setup()
{
	KAPC_STATE* kapc = {};
	PEPROCESS winlogon = 0;
	
	kapc = (_KAPC_STATE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(kapc), 0x141414);
	if (!kapc)
	{
		print("failed to allocate pool in hook");
		return;
	}
	
	if (!NT_SUCCESS(PsLookupProcessByProcessId(memory::user::GetProcID("winlogon.exe"), &winlogon)))
	{
		print("failed to lookup process in hook");
		return;
	}

	KeStackAttachProcess(winlogon, kapc);

	PVOID driverBase = memory::kernel::get_driver_module_base("\\SystemRoot\\System32\\win32kbase.sys");
	uintptr_t hookAddress = (uintptr_t)memory::kernel::find_pattern(driverBase, win32kbaseSize, "\x78\x3A\x4C\x8B\x15\x00\x00\x00\x00", "xxxxx????") + 2; // ApiSetEditionCreateDesktopEntryPoint (qword sub called)
	
	const uintptr_t hookAddress_deref = (uintptr_t)hookAddress + *(int*)((BYTE*)hookAddress + 3) + 7;

	//IMAGE_DOS_HEADER* peHeader = (IMAGE_DOS_HEADER*)driverBase;

	if (!hookAddress)
	{
		print("hook->Setup(): could not find hook address");
		return;
	}

	//print("code segment [%p]: ", peHeader->e_cs);
	print("non relative hook func: [%p]", HookFunction);

	*(PVOID*)&func = InterlockedExchangePointer((PVOID*)hookAddress_deref, (PVOID)HookFunction);

	print("address of pointer to function: [%p]", hookAddress_deref);
	print("address of our function: [%p]", HookFunction);
	print("address of the original function: [%p]", func);

	KeUnstackDetachProcess(kapc);
	ExFreePoolWithTag(kapc, 0x141414);

	print("Hook Setup");
}

