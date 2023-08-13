#pragma once

#include <Windows.h>

CHAR syscall_shellcode[] = {
	0x4c,0x8b,0xd1,		 //mov r10,rcx
	0xb8,0xb9,0x00,0x00,0x00, //mov eax,0B9h
	0x0f,0x05,		//syscall
	0xc3	       //ret
};

DOUBLE get_syscall_ID(const char* szFuncName)
{
	HMODULE hModule = GetModuleHandle("win32u.dll");
	DWORD64 FuncAddr = (DWORD64)GetProcAddress(hModule, (LPCSTR)szFuncName);
	return *(DOUBLE*)(FuncAddr + 4);
}

template <typename T>
T get_syscall_function(DOUBLE ID)
{
	CHAR shellcode[11];
	memcpy(&shellcode, &syscall_shellcode, sizeof(CHAR) * 11);
	memcpy(&shellcode + 4, &ID, sizeof(DOUBLE));
	return T(shellcode);
}
