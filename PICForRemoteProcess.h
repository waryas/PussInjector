#pragma once


/* Inspired by http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html */
/* And HLeaker from Schnocker */

#include <stdint.h>
#include <windows.h>
#include <winternl.h>

#include "XorString.h"

#define LOADLIBRARYA_HASH 0x0726774c
#define GETPROCESADDR_HASH 0x7802f749

//macro to make it easy for myself

#define INITPIC(a) 	auto pLoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(GetProcAddressWithHash(LOADLIBRARYA_HASH));\
					if (!pLoadLibraryA)\
						return a;\
					auto pGetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(GetProcAddressWithHash(GETPROCESADDR_HASH));\
					if (!pGetProcAddress)\
						return a;

#define PPCAT_NX(A, B) A ## B

#define PPCAT(A, B) PPCAT_NX(A, B)

#define ROTR32(value, shift) (((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

#define sText(var, s) volatile const char* PPCAT(tmp,var)= XorString(s); \
                      char* var = (char*)PPCAT(tmp,var);

#define _(s) (char*)XorString(s)

#define PIC(dll, func)  sText(PPCAT(sz,func), #func)\
						auto PPCAT(f,func) = reinterpret_cast<decltype(&func)>(pGetProcAddress(pLoadLibraryA((char*)dll), (char*)PPCAT(sz,func)));

#define _PIC(dll, func) sText(PPCAT(sz_,func), #func)\
						auto PPCAT(_,func) = reinterpret_cast<decltype(&func)>(pGetProcAddress(pLoadLibraryA((char*)dll), (char*)PPCAT(sz_,func)));

#define HOOKTARGET(target, function, lambda) installHook<decltype(function)>(target, _(#function), lambda);

#define HOOK(function, lambda) HOOKTARGET(0,function, lambda);

#if defined(_WIN64)
	#define READPEBADDR (PPEB)__readgsqword(0x60);
#elif defined(_M_ARM)
	#define READPEBADDR (PPEB)((ULONG_PTR)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0);\
	__emit(0x00006B1B);
#else 
	#define READPEBADDR (PPEB)__readfsdword(0x30);
#endif


#pragma optimize("ts", on )  
#pragma strict_gs_check(push, off)   
#pragma auto_inline(off)
#pragma check_stack(off)
#pragma code_seg(push, ".p")
    HMODULE GetProcAddressWithHash(_In_ DWORD dwModuleFunctionHash);
	template <typename T>
	FORCEINLINE uintptr_t installHook(char*, char*, T b);
	FORCEINLINE uintptr_t restoreHook(char* targetModule, char*fctName, void* origPointer);
	void __stdcall RemoteFunction(void);
	__declspec(noinline) void __stdcall end_marker(void);
#pragma strict_gs_check(pop)   
#pragma code_seg(pop)

typedef struct _MY_PEB_LDR_DATA {
	ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;


#define START_PIC_SECTION (uintptr_t)GetProcAddressWithHash
#define END_PIC_SECTION (uintptr_t)end_marker
#define SIZE_PIC_SECTION END_PIC_SECTION - START_PIC_SECTION
#define EP (uintptr_t)RemoteFunction - START_PIC_SECTION


