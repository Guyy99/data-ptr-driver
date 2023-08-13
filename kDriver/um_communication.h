#pragma once

#pragma warning (disable : 4700)

#include "syscall.h"




enum requests
{
	REQUEST_PEB,
	REQUEST_PID,
	REQUEST_MODULEBASE,
	REQUEST_READ,
	REQUEST_WRITE
};


// struct that will be interpreted once it is sent to kernel

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


static KM_REQ instructions;

typedef unsigned __int64 _QWORD;

//static __int64(__fastcall* NtUserCreateDesktopEx)(__int64, __int64, __int64, unsigned int, int, int); // prototype for the undocumented function
using NtUserCreateDesktopExPrototype = __int64(__fastcall*)(__int64, __int64, __int64, unsigned int, int, int);
NtUserCreateDesktopExPrototype NtUserCreateDesktopEx;


class driver
{
private:
	uintptr_t process_ID;

public:
	driver(const char* process_name)
	{
		NtUserCreateDesktopEx = get_syscall_function<NtUserCreateDesktopExPrototype>(get_syscall_ID("NtUserCreateDesktopEx"));

		process_ID = get_process_id(process_name);
	}
public:
	template <typename type>
	type get_read_memory(uintptr_t address)
	{
		type buffer;

		instructions.request = REQUEST_READ;
		instructions.address = address;
		instructions.size_of_buffer = sizeof(type);
		instructions.PID = process_ID;
		instructions.pBuffer = (void*)&buffer;

		

		NtUserCreateDesktopEx(0, 0, (__int64)&instructions, 0, 0, 0);

		return buffer;
	}

	template <typename type>
	void get_write_memory(uintptr_t address, type buffer)
	{
		instructions.request = REQUEST_WRITE;
		instructions.address = address;
		instructions.size_of_buffer = sizeof(type);
		instructions.PID = process_ID;
		instructions.pBuffer = (void*)&buffer;

		NtUserCreateDesktopEx(0, 0, (__int64)&instructions, 0, 0, 0);

	}

	uintptr_t get_process_id(const char* processName)
	{
		instructions.request = REQUEST_PID;
		instructions.processName = processName;
		instructions.PID = 0;

		NtUserCreateDesktopEx(0, 0, (__int64)&instructions, 0, 0, 0);

		return instructions.PID;
	}

	uintptr_t get_module_base_address()
	{
		uintptr_t buffer;

		instructions.request = REQUEST_MODULEBASE;
		instructions.PID = process_ID;
		instructions.pBuffer = (void*)&buffer;
		instructions.size_of_buffer = sizeof(buffer);

		NtUserCreateDesktopEx(0, 0, (__int64)&instructions, 0, 0, 0);

		return buffer;
	}
};
