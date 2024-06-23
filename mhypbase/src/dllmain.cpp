#include "pch.h"

#include <iostream>

DWORD WINAPI Thread(LPVOID lpParam)
{
	std::cout << "[AntiCheatEMU] Thread started" << std::endl;
	return 0;
}

HRESULT __cdecl Initialize()
{
	std::cout << "[AntiCheatEMU] Initialize called..." << std::endl;
	Sleep(500);
	while(true)
	{
		Sleep(30000);
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
		if (HANDLE hThread = CreateThread(NULL, 0, Thread, NULL, 0, NULL))
			CloseHandle(hThread);
	return TRUE;
}
