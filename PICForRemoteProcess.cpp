#include "PICForRemoteProcess.h"

#include <stdio.h>

/* 
   Everything in this file is position independant code that can be injected 
   and executed without relocation to any application 
*/

#pragma optimize("ts", on )  
#pragma strict_gs_check(push, off)   
#pragma auto_inline(off)
#pragma check_stack(off)
#pragma code_seg(push, ".p")
__declspec(dllexport) HMODULE GetProcAddressWithHash(_In_ DWORD dwModuleFunctionHash)
{
	PPEB PebAddress;
	PMY_PEB_LDR_DATA pLdr;
	PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
	PVOID pModuleBase;
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD dwExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	PLIST_ENTRY pNextModule;
	DWORD dwNumFunctions;
	USHORT usOrdinalTableIndex;
	PDWORD pdwFunctionNameBase;
	PCSTR pFunctionName;
	UNICODE_STRING BaseDllName;
	DWORD dwModuleHash;
	DWORD dwFunctionHash;
	PCSTR pTempChar;
	DWORD i;

	PebAddress = READPEBADDR

	pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
	pNextModule = pLdr->InLoadOrderModuleList.Flink;
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;

	while (pDataTableEntry->DllBase != NULL)	{
		dwModuleHash = 0;
		pModuleBase = pDataTableEntry->DllBase;
		BaseDllName = pDataTableEntry->BaseDllName;
		pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
		dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
		pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

		if (dwExportDirRVA == 0)
			continue;

		for (i = 0; i < BaseDllName.MaximumLength; i++) {
			pTempChar = ((PCSTR)BaseDllName.Buffer + i);
			dwModuleHash = ROTR32(dwModuleHash, 13);
			if (*pTempChar >= 0x61)
				dwModuleHash += *pTempChar - 0x20;
			else
				dwModuleHash += *pTempChar;
		}

		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);
		dwNumFunctions = pExportDir->NumberOfNames;
		pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

		for (i = 0; i < dwNumFunctions; i++) {
			dwFunctionHash = 0;
			pFunctionName = (PCSTR)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
			pdwFunctionNameBase++;
			pTempChar = pFunctionName;

			do {
				dwFunctionHash = ROTR32(dwFunctionHash, 13);
				dwFunctionHash += *pTempChar;
				pTempChar++;
			} while (*(pTempChar - 1) != 0);

			dwFunctionHash += dwModuleHash;

			if (dwFunctionHash == dwModuleFunctionHash) {
				usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
				return (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
			}
		}
	}
	return NULL;
}



__declspec(dllexport) void __stdcall RemoteFunction() {

	auto pLoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(GetProcAddressWithHash(LOADLIBRARYA_HASH));
	if (!pLoadLibraryA)
		return;
	auto pGetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(GetProcAddressWithHash(GETPROCESADDR_HASH));
	if (!pGetProcAddress)
		return;

	//NON CRT LOAD	

	sText(szKernel32Dll, "kernel32.dll");
	sText(szUser32Dll, "user32.dll");
	sText(szNtdllDll, "ntdll.dll");

	PIC(szUser32Dll, MessageBoxA);
	PIC(szKernel32Dll, SetConsoleTitleA);
	PIC(szKernel32Dll, OpenProcess);
	PIC(szKernel32Dll, WriteProcessMemory);
	PIC(szKernel32Dll, ReadProcessMemory);
	PIC(szKernel32Dll, GetModuleFileNameA);
	PIC(szKernel32Dll, AllocConsole);

	//CRT LOAD

	sText(szMsvrtDll, "msvcrt.dll");

	_PIC(szMsvrtDll, fopen);
	_PIC(szMsvrtDll, fprintf);
	_PIC(szMsvrtDll, fclose);
	_PIC(szMsvrtDll, printf);
	_PIC(szMsvrtDll, sprintf);
	_PIC(szMsvrtDll, system);
	_PIC(szMsvrtDll, freopen);

	//Small fixup because VS17 doesn't use msvcrt.dll 
	_CRTIMP FILE * __cdecl __iob_func(void);
	_PIC(szMsvrtDll, __iob_func);
	
	volatile char buffer[256];
	volatile char buffer2[256];

	fAllocConsole();
	fSetConsoleTitleA(_("Nigga"));
	fGetModuleFileNameA(0, (char*)buffer, 256);
	_sprintf((char*)buffer2, _("\nI am inside %s\n"), buffer);
	fMessageBoxA(NULL, (char*)buffer2, _("This is a 100% PIC function!!!!"), MB_OK);

}

#pragma optimize("", off)
__declspec(dllexport, noinline) void __stdcall end_marker(void) {
	end_marker();
	return;
}
#pragma optimize("", on)
#pragma strict_gs_check(pop)   
#pragma code_seg(pop)