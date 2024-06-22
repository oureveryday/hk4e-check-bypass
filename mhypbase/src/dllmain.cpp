#include "pch.h"

DWORD WINAPI Thread(LPVOID lpParam)
{
	return 0;
}

HRESULT __cdecl Initialize()
{
	while(true)
	{
		Sleep(10000);
	}
	return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
		if (HANDLE hThread = CreateThread(NULL, 0, Thread, NULL, 0, NULL))
			CloseHandle(hThread);
	return TRUE;
}
