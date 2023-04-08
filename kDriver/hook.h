#pragma once

#include <cstdint>

#define win32kbaseSize 0x294600

struct READ_WRITE
{
	uintptr_t key;
	bool request_PID;
	bool request_module_base;
	bool request_read;
	bool request_write;
	bool request_PEB;
	const char* processName;
	const char* moduleName;
	uintptr_t PID;
	uintptr_t address;
	uintptr_t PEB;
	void* pBuffer;
	uintptr_t moduleBase;
	size_t size_of_buffer;
	bool operation_success;

};

namespace hook
{
	void Setup();
}


