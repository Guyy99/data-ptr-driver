#pragma once

#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <windef.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include <windef.h>
#include <cstdint>
#include <cstddef>

#pragma comment(lib, "ntoskrnl.lib")

#define print(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)

