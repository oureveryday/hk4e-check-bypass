#include "pch.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return TRUE;
}

HRESULT __cdecl Initialize()
{
	LoadLibraryA("mhypbase.dll");
	OutputDebugStringW(L"[AntiCheatEMU] Initialize");
	OutputDebugStringW(L"[AntiCheatEMU] TerminateThread");
	TerminateThread(GetCurrentThread(),0);
	return false;
}


