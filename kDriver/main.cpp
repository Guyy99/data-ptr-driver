#include "includes.h"
#include "memory.h"
#include "hook.h"

NTSTATUS DriverEntry(PVOID mappedImageBase, PVOID mappedImageSize)
{
	print("Mapped [%p] w/ Size [0x%x]\n", mappedImageBase, mappedImageSize);

	print("DRIVER LOADED");

	/*
	HANDLE pID = memory::user::GetProcID("cmd.exe");
	print("ProcID of cmd.exe: [%p]\n", pID);
	PVOID baseAddress = memory::user::GetBaseAddress(pID);
	print("Base Address of cmd: [%p]\n", baseAddress);
	PVOID driverBase = memory::kernel::get_driver_module_base("\\SystemRoot\\System32\\win32kbase.sys");
	print("base address of win32kbase.sys: [%p]\n", driverBase);
	*/

	hook::Setup();

	return STATUS_SUCCESS;
}
