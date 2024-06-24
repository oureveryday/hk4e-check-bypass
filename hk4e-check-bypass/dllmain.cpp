#include "pch.h"

#include "Console.h"
#include "detours.h"
#include <codecvt>
#include <fstream>
#include <intrin.h>
#include <regex>
#include <string>
#include <thread>
#include <vector>
#include <winternl.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ntdll.lib")



struct Replace
{
	std::wstring origname;
	std::wstring replacename;
	bool replaceonfirsttime;    // Replace reading request after reading for first time
	bool firstime = false;        // first time read indicator, should always be false
};

//----------Configuration start---------------

bool debugprintpath = false;    //Print the path of the file being read

bool enabledebuglogfile = false;      //Enable debug log file

std::string logfilename = "hk4eCheckBypass.log"; //Log file name

std::vector<Replace> internalreplaceList = {
		{L"version.dll", L"version.del", false, false},
			{L"MHYPBase.dll",L"MHYPBase.org.dll",true,false},
};//internal replace list example

//----------Configuration end-----------------


#pragma region Utils
bool isFileExist(const wchar_t* fileName) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return true;
	}
	return false;
}

void PrintLog(std::string str)
{
	std::string logstr = "[hk4eCheckBypass] " + str + "\n";
#ifdef _DEBUG
	Console::Print(logstr.c_str());
	if (enabledebuglogfile)
	{
		std::ofstream logfile;
		logfile.open(logfilename, std::ios_base::app);
		logfile << logstr;
	}
#endif
	int wideStrLength = MultiByteToWideChar(CP_UTF8, 0, logstr.c_str(), -1, nullptr, 0);
	wchar_t* wideString = new wchar_t[wideStrLength];
	MultiByteToWideChar(CP_UTF8, 0, logstr.c_str(), -1, wideString, wideStrLength);
	OutputDebugString(wideString);
	delete[] wideString;
}

wchar_t const* GetCurrentPath()
{
	wchar_t exePath[MAX_PATH];
	GetModuleFileNameW(NULL, exePath, MAX_PATH);
	wchar_t* lastBackslash = wcsrchr(exePath, L'\\');
	if (lastBackslash != nullptr) {
		*lastBackslash = L'\0';  // Null-terminate to get the directory path
	}
	return exePath;
}

std::wstring utf8ToUtf16(const std::string& utf8Str)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
	return conv.from_bytes(utf8Str);
}

std::string utf16ToUtf8(const std::wstring& utf16Str)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
	return conv.to_bytes(utf16Str);
}

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;
EXTERN_C NTSTATUS __stdcall NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer, ULONG InformationBufferSize, PULONG ResultLength);
EXTERN_C NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG  NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
EXTERN_C NTSTATUS __stdcall NtPulseEvent(HANDLE EventHandle, PULONG PreviousState);

uintptr_t PatternScan(LPCSTR module, LPCSTR pattern)
{
	static auto pattern_to_byte = [](const char* pattern) {

		auto bytes = std::vector<int>{};

		auto start = const_cast<char*>(pattern);

		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
		};

	auto mod = GetModuleHandleA(module);
	if (!mod)
		return 0;

	auto dosHeader = (PIMAGE_DOS_HEADER)mod;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)mod + dosHeader->e_lfanew);
	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = pattern_to_byte(pattern);
	auto scanBytes = reinterpret_cast<std::uint8_t*>(mod);
	auto s = patternBytes.size();
	auto d = patternBytes.data();

	for (auto i = 0ul; i < sizeOfImage - s; ++i) {
		bool found = true;
		for (auto j = 0ul; j < s; ++j) {
			if (scanBytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}

		if (found) {
			return (uintptr_t)&scanBytes[i];
		}
	}
	return 0;
}

void DisableVMP()
{
	// restore hook at NtProtectVirtualMemory
	auto ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) return;

	bool linux = GetProcAddress(ntdll, "wine_get_version") != nullptr;
	void* routine = linux ? (void*)NtPulseEvent : (void*)NtQuerySection;
	DWORD old;
	VirtualProtect(NtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
	*(uintptr_t*)NtProtectVirtualMemory = *(uintptr_t*)routine & ~(0xFFui64 << 32) | (uintptr_t)(*(uint32_t*)((uintptr_t)routine + 4) - 1) << 32;
	VirtualProtect(NtProtectVirtualMemory, 1, old, &old);
}
#pragma endregion

#pragma region DisableAntiCheat
//From Akebi-GC

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

static PVOID GetLibraryProcAddress(LPCSTR LibraryName, LPCSTR ProcName)
{
	auto hModule = GetModuleHandleA(LibraryName);
	if (hModule == NULL)
		return nullptr;
	return GetProcAddress(hModule, ProcName);
}

bool CloseHandleByName(const wchar_t* name)
{
	auto pid = GetCurrentProcessId();

	while (true)
	{
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
			break;

		Sleep(2000);
	}
	Sleep(8000);
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
	NTSTATUS status;

	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	HANDLE processHandle = GetCurrentProcess();
	ULONG i;

	/* NtQuerySystemInformation won't give us the correct buffer size,
		so we guess by doubling the buffer size. */
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
	if (!NT_SUCCESS(status))
	{
		PrintLog("NtQuerySystemInformation failed!");
		return false;
	}

	bool closed = false;
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		if (closed)
			break;

		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		/* Duplicate the handle so we can query it. */
		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
			continue;

		/* Query the object type. */
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			CloseHandle(dupHandle);
			continue;
		}

		/* Query the object name (unless it has an access of
			0x0012019f, on which NtQueryObject could hang. */
		if (handle.GrantedAccess == 0x0012019f)
		{
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
		{
			/* Reallocate the buffer and try again. */
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
			{
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}

		/* Cast our buffer into an UNICODE_STRING. */
		objectName = *(PUNICODE_STRING)objectNameInfo;

		/* Print the information! */
		if (objectName.Length && lstrcmpiW(objectName.Buffer, name) == 0)
		{
			CloseHandle((HANDLE)handle.Handle);
			closed = true;
		}

		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);

	}

	free(handleInfo);
	CloseHandle(processHandle);
	return closed;
}

bool CloseAntiCheatHandle()
{
	auto pid = GetCurrentProcessId();

	while (true)
	{
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
			break;

		Sleep(2000);
	}

	Sleep(8000);
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
	NTSTATUS status;

	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	HANDLE processHandle = GetCurrentProcess();
	ULONG i;

	/* NtQuerySystemInformation won't give us the correct buffer size,
		so we guess by doubling the buffer size. */
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
	if (!NT_SUCCESS(status))
	{
		PrintLog("NtQuerySystemInformation failed!");
		return false;
	}

	bool closed = false;
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		/* Duplicate the handle so we can query it. */
		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
			continue;

		/* Query the object type. */
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			CloseHandle(dupHandle);
			continue;
		}

		/* Query the object name (unless it has an access of
			0x0012019f, on which NtQueryObject could hang. */
		if (handle.GrantedAccess == 0x0012019f)
		{
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
		{
			/* Reallocate the buffer and try again. */
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
			{
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}

		/* Cast our buffer into an UNICODE_STRING. */
		objectName = *(PUNICODE_STRING)objectNameInfo;

		std::regex HandleRegex1("\\\\Sessions\\\\1\\\\BaseNamedObjects\\\\HoYoG.*");
		std::regex HandleRegex2("\\\\Sessions\\\\1\\\\BaseNamedObjects\\\\[0-9A-Fa-f]{32,}");
		/* Print the information! */
		if (objectName.Length)
		{
			std::string HandleName = utf16ToUtf8(objectName.Buffer);
			if (std::regex_search(HandleName, HandleRegex1))
			{
				CloseHandle((HANDLE)handle.Handle);
				PrintLog("Closed handle " + HandleName);
				closed = true;
			}
			if (std::regex_search(HandleName, HandleRegex2))
			{
				CloseHandle((HANDLE)handle.Handle);
				PrintLog("Closed handle " + HandleName);
				closed = true;
			}
		}
		
		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}
	free(handleInfo);
	CloseHandle(processHandle);
	return closed;
}
#pragma endregion

std::vector<Replace> replaceList;

typedef NTSTATUS(WINAPI* pNtCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength);

pNtCreateFile oNtCreateFile = nullptr;

typedef NTSTATUS(WINAPI* pNtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions);

pNtOpenFile oNtOpenFile = nullptr;

std::wstring GetReplacedPath(std::wstring path)
{
	// Get the file name from the path
	size_t lastSlash = path.find_last_of('/');
	size_t lastBackslash = path.find_last_of('\\');
	size_t lastSeparator = (lastSlash > lastBackslash) ? lastSlash : lastBackslash;
	std::wstring filename = path.substr(lastSeparator + 1);
	if (filename.find(utf8ToUtf16(logfilename)) == std::string::npos && debugprintpath)
	{
		PrintLog("Reading Path:" + utf16ToUtf8(path));
	}
	// Check if the file name matches any entry in the replaceList
	for (Replace& replace : replaceList)
	{
		if (filename.find(replace.origname) != std::wstring::npos)
		{
			if (replace.replaceonfirsttime && replace.firstime)
			{
				PrintLog("Reading " + utf16ToUtf8(replace.origname) + " after first time.");
				break;
			}
			replace.firstime = true;
			PrintLog("Reading " + utf16ToUtf8(replace.origname) + ",Replacing...");
			// Replace the path's filename with replacename
			size_t pos = path.find_last_of(L"/\\");
			path = path.substr(0, pos + 1) + replace.replacename;
			PrintLog("Replaced Path:" + utf16ToUtf8(path));
			// Set firstime to true if replaceafterfirsttime is true and firstime is false
			

			break; // No need to check further once a replacement is made
		}
	}

	return path;
}

NTSTATUS WINAPI NtCreateFileHook(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength)
{
	try
	{
		if (ObjectAttributes != nullptr && ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Length &&
		ObjectAttributes->ObjectName->Buffer != nullptr && !IsBadReadPtr(ObjectAttributes->ObjectName->Buffer, sizeof(WCHAR)) && ObjectAttributes->ObjectName->Buffer[0]) {
		std::wstring originalPath(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(WCHAR));
		std::wstring replacedPathStr = GetReplacedPath(originalPath);
		UNICODE_STRING replacedPathUnicode;
		RtlInitUnicodeString(&replacedPathUnicode, replacedPathStr.c_str());
		ObjectAttributes->ObjectName = &replacedPathUnicode;
		return oNtCreateFile(
				FileHandle,
				DesiredAccess,
				ObjectAttributes,
				IoStatusBlock,
				AllocationSize,
				FileAttributes,
				ShareAccess,
				CreateDisposition,
				CreateOptions,
				EaBuffer,
				EaLength);
		}
	}
	catch (...)
	{
		PrintLog("Error in NtCreateFileHook");
	}
	return oNtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);
}

NTSTATUS WINAPI NtOpenFileHook(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions)
{
	try
	{
		if (ObjectAttributes != nullptr && ObjectAttributes->ObjectName &&
			ObjectAttributes->ObjectName->Length &&
			ObjectAttributes->ObjectName->Buffer != nullptr && !IsBadReadPtr(ObjectAttributes->ObjectName->Buffer, sizeof(WCHAR)) && ObjectAttributes->ObjectName->Buffer[0]) {
			std::wstring originalPath(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(WCHAR));
			std::wstring replacedPathStr = GetReplacedPath(originalPath);
			UNICODE_STRING replacedPathUnicode;
			RtlInitUnicodeString(&replacedPathUnicode, replacedPathStr.c_str());
			ObjectAttributes->ObjectName = &replacedPathUnicode;
			return oNtOpenFile(
				FileHandle,
				DesiredAccess,
				ObjectAttributes,
				IoStatusBlock,
				ShareAccess,
				OpenOptions);
		}
	}
	catch (...)
	{
		PrintLog("Error in NtOpenFileHook");
	}
    return oNtOpenFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        ShareAccess,
        OpenOptions);
}

void LoadHook()
{
	PrintLog("Starting to hook File APIs...");
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (hNtdll)
	{
		oNtCreateFile = (pNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
		if (oNtCreateFile)
		{
			DetourAttach(&(PVOID&)oNtCreateFile, NtCreateFileHook);
			auto Error = DetourTransactionCommit();
			if (Error == NO_ERROR)
				PrintLog("Hooked NtCreateFile");
			else
				PrintLog("NtCreateFile Hook Failed. Error: " + std::to_string(Error));
		}
		else
		{
			PrintLog("NtCreateFile Hook Failed. Error: Failed to get NtCreateFile address.");
		}
	}

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (hNtdll)
	{
		oNtOpenFile = (pNtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
		if (oNtOpenFile)
		{
			DetourAttach(&(PVOID&)oNtOpenFile, NtOpenFileHook);
			auto Error = DetourTransactionCommit();
			if (Error == NO_ERROR)
				PrintLog("Hooked NtOpenFile");
			else
				PrintLog("NtOpenFile Hook Failed. Error: " + std::to_string(Error));
		}
		else
		{
			PrintLog("NtOpenFile Hook Failed. Error: Failed to get NtOpenFile address.");
		}
	}
}
void GetReplaceList()
{
	replaceList = internalreplaceList;
	PrintLog("-----------------");
	PrintLog("Replace List:");
	{
		for (const auto& replace : replaceList) {
			PrintLog(utf16ToUtf8(replace.origname) + "," + utf16ToUtf8(replace.replacename));
		}
	}
	PrintLog("-----------------");
}

PVOID ocheck = nullptr;

void __fastcall checkHook(int num, void* b, void* c, void* d, void* e)
{
    PrintLog("Triggered hook " + std::to_string(num));
	if (num == 8)
	{
		num = 17;
		PrintLog("Replaced to " + std::to_string(num));
	}
	DetourDetach(&ocheck, checkHook);
	(decltype(&checkHook)(ocheck)(num, b, c, d, e));
	DetourAttach(&ocheck, checkHook);
	return;
}

void Init()
{
	PrintLog("hk4e check bypass Init");
	std::thread([]() {
		Sleep(100);
		DisableVMP();
		auto checkaddr = PatternScan("UnityPlayer.dll", "55 41 57 41 56 41 54 56 57 53 48 81 EC 90 02 00 00");

		if (!checkaddr || checkaddr % 16 > 0)
			PrintLog("Not find check addr.");

		PVOID check = (PVOID)checkaddr;
		if (!check)
			PrintLog("Failed to hook check addr.");

		ocheck = check;
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
        DetourAttach(&ocheck, checkHook);
		DetourTransactionCommit();
		}).detach();
	

	/*
	GetReplaceList();
	std::thread([]() {
		DisableVMP();
		LoadHook();
		}).detach();
	std::thread([]() {
		PrintLog("Disabling AntiCheat...");
		if (CloseAntiCheatHandle())
		{
			PrintLog("Disabled AntiCheat Handles");
		}
		else {
			PrintLog("Disable AntiCheat Handles failed");
		}
		if (CloseHandleByName(L"\\Device\\HoYoProtect"))
		{
			PrintLog("Disabled HoYoProtect");
		}
		else {
			PrintLog("Disable HoYoProtect failed");
		}
		}).detach();
	*/
}

// 55 41 57 41 56 41 54 56 57 53 48 81 EC 90 02 00 00
// rcx = 11 after load
// rcx = 8 before load

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
#ifdef _DEBUG
	Console::Attach();
#endif
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		PrintLog("hk4e check bypass dll Loaded.");
		Init();
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) void hk4eCheckBypass() {};