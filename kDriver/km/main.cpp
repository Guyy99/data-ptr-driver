#include "hook/hook.h"
#include "includes.h"




NTSTATUS DriverEntry(PVOID mappedImageBase, PVOID mappedImageSize)
{
	print("Mapped [%p] w/ Size [0x%x]\n", mappedImageBase, mappedImageSize);

	print("DRIVER LOADED");

	hook::Setup();

	return STATUS_SUCCESS;
}
