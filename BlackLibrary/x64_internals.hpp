#pragma once

#include <Windows.h>

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
{ \
	EMIT(0x6A) EMIT(_cs)																		/*  push _cs					*/ \
	EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00)										/*  call $+5					*/ \
	EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x05)													/*  add dword [esp],5			*/ \
	EMIT(0xCB)																					/*  retf						*/ \
}

#define X64_End_with_CS(_cs) \
{ \
	EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00)										/*  call $+5					*/ \
	EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(0x04) EMIT(_cs) EMIT(0x00) EMIT(0x00) EMIT(0x00)		/*  mov dword [rsp+4], _cs		*/ \
	EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x0D)      											/*  add dword [rsp], 0xD		*/ \
	EMIT(0xCB)                             														/*  retf						*/ \
}

#define X64_Start()		X64_Start_with_CS(0x33)
#define X64_End()		X64_End_with_CS(0x23)

#define X64_Push(r)		EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r)		EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W			EMIT(0x48) __asm

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

union x64_reg
{
	DWORD64 qw;
	DWORD dw[2];
};