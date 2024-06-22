#include "pch.h"

#include <codecvt>

#include "Console.h"
#include "detours.h"
#include <fstream>
#include <intrin.h>
#include <iostream>
#include <map>
#include <sstream>
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
	bool replaceafterfirsttime;    // Replace reading request after reading for first time
	bool firstime = false;        // first time read indicator, should always be false
};

//----------Configuration start---------------

bool debugprintpath = false;    //Print the path of the file being read

bool enabledebuglogfile = true;      //Enable debug log file

std::string logfilename = "hk4eCheckBypass.log"; //Log file name

std::vector<Replace> internalreplaceList = {
		{L"version.dll", L"version.del", false, false},
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
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
	NTSTATUS status;

	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	ULONG pid = 0;
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
			
			replace.firstime = true;

			if (replace.replaceafterfirsttime && !replace.firstime)
			{
				PrintLog("Reading " + utf16ToUtf8(replace.origname) + "for first time.");
				break;
			}
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

void Init()
{
	PrintLog("hk4e check bypass Init");
	GetReplaceList();
	std::thread([]() {
		DisableVMP();
		CloseHandleByName(L"\\Device\\HoYoProtect");
		LoadHook();
		}).detach();
}

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

extern "C" __declspec(dllexport) void SteamAPICheckBypass() {};