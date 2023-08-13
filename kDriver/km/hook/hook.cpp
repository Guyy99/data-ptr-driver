#include "hook.h"
#include "../memory/memory.h"

typedef unsigned __int64 _QWORD;

typedef __int64(__fastcall* Qword_ptrOriginal)(_QWORD, _QWORD, _QWORD, _QWORD, DWORD, DWORD);
Qword_ptrOriginal func;


__int64 __fastcall HookFunction(_QWORD a1, _QWORD a2, _QWORD a3, _QWORD a4, DWORD a5, DWORD a6) // handles um instructions
{
	print("hooked func called");
	
	print("a1 [%p]", a1);
	print("a2 [%p]", a2);
	print("a3 [%p]", a3);
	print("a4 [%p]", a4);
	print("a5 [%p]", a5);
	print("a6 [%p]", a6);

	if (!a3)
	{
		print("arg is null");
		return func(a1, a2, a3, a4, a5, a6);
	}

	KM_REQ* instructions = (KM_REQ*)a3;

	if (instructions->key != 0x69420)
		return func(a1, a2, a3, a4, a5, a6);

	if (instructions->request == REQUEST_PID)
	{
		print("process [%p]", instructions->processName);
		instructions->PID = (uintptr_t)memory::user::GetProcID(instructions->processName);

		return 0;
	}
	else if (instructions->request == REQUEST_MODULEBASE)
	{
		*(uintptr_t*)instructions->pBuffer = (uintptr_t)memory::user::GetBaseAddress((HANDLE)instructions->PID);

		return 0;

	}
	else if (instructions->request == REQUEST_READ)
	{
		print("address of buffer [%p]", instructions->pBuffer);
		SIZE_T size;
		memory::kernel::physical::ReadVirtual((int)instructions->PID, (uint64_t)instructions->address, (uint64_t)instructions->pBuffer, instructions->size_of_buffer, &size);

		return 0;
	}
	else if (instructions->request == REQUEST_WRITE)
	{
		memory::user::write_memory((HANDLE)instructions->PID, (PVOID)instructions->address, (PVOID)instructions->pBuffer, instructions->size_of_buffer);

		return 0;
	}
	else if (instructions->request == REQUEST_PEB)
	{
		*(uintptr_t*)instructions->pBuffer = (uintptr_t)memory::user::GetPEB((HANDLE)instructions->PID);

		return 0;
	}

	return 0;
}



void hook::Setup()
{
	KAPC_STATE* kapc = {};
	PEPROCESS winlogon = 0;
	
	kapc = (_KAPC_STATE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(kapc), 0x141414); // allocates pool memory for struct that is returned when attatching the process used in win32kbase.sys
	if (!kapc)
	{
		print("failed to allocate pool in hook");
		return;
	}
	
	if (!NT_SUCCESS(PsLookupProcessByProcessId(memory::user::GetProcID("winlogon.exe"), &winlogon))) // "winlogon.exe" is a process that communicates with win32kbase.sys
	{
		print("failed to lookup process in hook");
		return;
	}



	PVOID driverBase = memory::kernel::get_driver_module_base("\\SystemRoot\\System32\\win32kbase.sys");
	uintptr_t hookAddress = (uintptr_t)memory::kernel::find_pattern(driverBase, win32kbaseSize, "\x78\x3A\x4C\x8B\x15\x00\x00\x00\x00", "xxxxx????") + 2; // ApiSetEditionCreateDesktopEntryPoint (qword sub called)
	
	const uintptr_t hookAddress_deref = (uintptr_t)hookAddress + *(int*)((BYTE*)hookAddress + 3) + 7; // gets relative address of pointer


	if (!hookAddress)
	{
		print("hook->Setup(): could not find hook address");
		return;
	}

	print("non relative hook func: [%p]", HookFunction);

	*(PVOID*)&func = InterlockedExchangePointer((PVOID*)hookAddress_deref, (PVOID)HookFunction); // swaps pointer to pointer of our function

	print("address of pointer to function: [%p]", hookAddress_deref);
	print("address of our function: [%p]", HookFunction);
	print("address of the original function: [%p]", func);

	// free memory and unattatch process

	ExFreePoolWithTag(kapc, 0x141414);

	print("Hook Setup");
}

