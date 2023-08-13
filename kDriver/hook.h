#pragma once

#include <cstdint>



#define win32kbaseSize 0x294600

enum requests
{
	REQUEST_PEB,
	REQUEST_PID,
	REQUEST_MODULEBASE,
	REQUEST_READ,
	REQUEST_WRITE
};

struct KM_REQ
{
	uintptr_t key = 0x69420;
	uintptr_t request;
	uintptr_t address;
	uintptr_t PID;
	const char* processName;
	const char* moduleName;
	void* pBuffer;
	uintptr_t size_of_buffer;
};

namespace hook
{
	void Setup();
}


