#include "pch.h"

#include <iostream>
#include <string>
#include <winternl.h>
#include <windows.h>
#include <filesystem>

#pragma comment(lib, "ntdll.lib")

void DisableLogReport()
{
	char szProcessPath[MAX_PATH]{};
	GetModuleFileNameA(nullptr, szProcessPath, MAX_PATH);

	auto path = std::filesystem::path(szProcessPath);
	auto ProcessName = path.filename().string();
	ProcessName = ProcessName.substr(0, ProcessName.find_last_of('.'));

	auto Astrolabe = path.parent_path() / (ProcessName + "_Data\\Plugins\\Astrolabe.dll");
	auto MiHoYoMTRSDK = path.parent_path() / (ProcessName + "_Data\\Plugins\\MiHoYoMTRSDK.dll");

	// open exclusive access to these two dlls
	// so they cannot be loaded
	HANDLE hFile = CreateFileA(Astrolabe.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	hFile = CreateFileA(MiHoYoMTRSDK.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

bool TlsOnce = false;

void __stdcall TlsCallback_0(PVOID hModule, DWORD fdwReason, PVOID pContext)
{
	Sleep(20);
	OutputDebugStringW(L"[AntiCheatEMU] TlsCallback_0");
	if (!TlsOnce)
	{
		DisableLogReport();
		TlsOnce = true;
	}
}

int num = 0;

HRESULT __cdecl Initialize()
{
	OutputDebugStringW(L"[AntiCheatEMU] Initialize");

	auto pid = GetCurrentProcessId();
	while (true)
	{
		num = num + 1;
		EnumWindows([](HWND hwnd, LPARAM lParam)->BOOL __stdcall
		{
			DWORD wndpid = 0;
			GetWindowThreadProcessId(hwnd, &wndpid);

			char szWindowClass[256]{};
			GetClassNameA(hwnd, szWindowClass, 256);
			if (!strcmp(szWindowClass, "UnityWndClass") && wndpid == *(DWORD*)lParam)
			{
				*(DWORD*)lParam = 0;
				return FALSE;
			}

			return TRUE;

		}, (LPARAM)&pid);

		if (!pid)
		{
			OutputDebugStringW(L"[AntiCheatEMU] TerminateThread");
			TerminateThread(GetCurrentThread(), 0);
			break;
		}

		OutputDebugStringW((std::wstring(L"[AntiCheatEMU] Waiting ") + std::to_wstring(num)).c_str());
		Sleep(2000);

		if (num > 5)
		{
			OutputDebugStringW(L"[AntiCheatEMU] Load time out, please try launch game again.");
			MessageBoxA(NULL, "[AntiCheatEMU] Load time out, please try launch game again.", "Error", MB_ICONERROR);
			ExitProcess(0);
		}
	}

	return false;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	OutputDebugStringW(L"[AntiCheatEMU] DllMain");
	return TRUE;
}

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback_0;
