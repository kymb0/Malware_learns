// ProcEnum.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#include <WtsApi32.h>
#include <Psapi.h>

#pragma comment(lib, "wtsapi32")
#pragma comment(lib, "ntdll")

#define STATUS_BUFFER_TOO_SMALL 0xC0000004

enum SYSTEM_INFORMATION_CLASS {
	SystemExtendedProcessInformation = 57
};

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	int BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION;

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

int ProcEnumWithToolhelp();
int ProcEnumWithWTS();
int ProcEnumWithEnumProc();
int ProcEnumWithNtQuerySystem();

bool EnableDebugPrivilege() {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		return false;

	BOOL success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	CloseHandle(hToken);

	return success && GetLastError() == ERROR_SUCCESS;
}

int Error(const char* text) {
	printf("%s (%u)\n", text, GetLastError());
	return 1;
}

int Usage() {
	printf("Usage: procenum <method>\n");
	printf("\t<method>: 1 - use ToolHelp\n");
	printf("\t<method>: 2 - use WTS\n");
	printf("\t<method>: 3 - use EnumProcesses\n");
	printf("\t<method>: 4 - use NtQuerySystemInformation\n");

	return 0;
}

int main(int argc, const char* argv[]) {
	if (argc == 1)
		return Usage();

	EnableDebugPrivilege();

	switch (atoi(argv[1])) {
		case 1:
			printf("Using ToolHelp...\n");
			return ProcEnumWithToolhelp();

		case 2:
			printf("Using WTS...\n");
			return ProcEnumWithWTS();

		case 3:
			printf("Using EnumProcesses...\n");
			return ProcEnumWithEnumProc();

		case 4:
			printf("Using NtQuerySystemInformation...\n");
			return ProcEnumWithNtQuerySystem();
	}

	printf("Unknown option... %s\n", argv[1]);
	return Usage();
}

std::wstring GetUserNameFromSid(PSID sid) {
	if (sid == nullptr)
		return L"";

	WCHAR name[32], domain[32];
	DWORD len = _countof(name);
	DWORD domainLen = _countof(domain);
	SID_NAME_USE use;
	if (!LookupAccountSid(nullptr, sid, name, &len, domain, &domainLen, &use))
		return L"";

	return std::wstring(domain) + L"\\" + name;
}

int ProcEnumWithToolhelp() {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return Error("Failed to create snapshot");

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	if (!Process32First(hSnapshot, &pe))
		return Error("Failed in Process32First");

	do {
		printf("PID:%6u (PPID:%6u) (Threads: %3u) (Priority: %2u): %ws\n",
			pe.th32ProcessID, pe.th32ParentProcessID, 
			pe.cntThreads, pe.pcPriClassBase, pe.szExeFile);
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);
	return 0;
}

int ProcEnumWithWTS() {
	DWORD level = 1;
	PWTS_PROCESS_INFO_EX info;
	DWORD count;
	if (!WTSEnumerateProcessesEx(WTS_CURRENT_SERVER_HANDLE, &level, 
		WTS_ANY_SESSION, (PWSTR*)&info, &count))
		return Error("Failed in calling WTSEnumerateProcessesEx");

	for (DWORD i = 0; i < count; i++) {
		PWTS_PROCESS_INFO_EX pinfo = info + i;
		printf("PID: %6u Session: %u (%ws) Username: %ws\n",
			pinfo->ProcessId, pinfo->SessionId, pinfo->pProcessName, 
			GetUserNameFromSid(pinfo->pUserSid).c_str());
	}

	WTSFreeMemoryEx(WTSTypeProcessInfoLevel1, info, count);

	return 0;
}

int ProcEnumWithEnumProc() {
	DWORD size = 512 * sizeof(DWORD);
	DWORD* ids = nullptr;
	DWORD needed = 0;

	//DWORD pids[10000];
	//EnumProcesses(pids, sizeof(pids), &needed);

	for (;;) {
		ids = (DWORD*)realloc(ids, size);
		if (ids == nullptr)
			break;

		if (!EnumProcesses(ids, size, &needed)) {
			free(ids);
			return Error("Failed in EnumProcesses");
		}
		if (size >= needed)
			break;

		size = needed + sizeof(DWORD) * 16;
	}
	if (ids == nullptr)
		return Error("Out of memory");

	WCHAR name[MAX_PATH];
	for (DWORD i = 0; i < needed / sizeof(DWORD); i++) {
		DWORD id = ids[i];
		printf("PID: %6u", id);
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, id);
		if (hProcess) {
			DWORD size = _countof(name);
			if (QueryFullProcessImageName(hProcess, 0, name, &size)) {
				printf(" %ws", name);
			}
			CloseHandle(hProcess);
		}
		printf("\n");
	}

	free(ids);
	return 0;
}

int ProcEnumWithNtQuerySystem() {
	// allocate large-enough buffer
	ULONG size = 1 << 18;
	void* buffer = nullptr;
	
	for (;;) {
		buffer = realloc(buffer, size);
		if (!buffer)
			return 1;

		ULONG needed;
		NTSTATUS status = NtQuerySystemInformation(SystemExtendedProcessInformation, buffer, size, &needed);
		if (status == 0)	// success
			break;

		if (status == STATUS_BUFFER_TOO_SMALL) {
			size = needed + (1 << 12);
			continue;
		}
		// some other error
		return status;
	}

	auto p = (SYSTEM_PROCESS_INFORMATION*)buffer;
	for (;;) {
		printf("PID: %6u PPID: %6u, Session: %u, Threads: %3u %ws\n",
			HandleToULong(p->UniqueProcessId), 
			HandleToULong(p->InheritedFromUniqueProcessId), 
			p->SessionId, p->NumberOfThreads,
			p->ImageName.Buffer ? p->ImageName.Buffer : L"");
		
		if (p->NextEntryOffset == 0)	// enumeration end
			break;

		p = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
	}
	free(buffer);

	return 0;
}

