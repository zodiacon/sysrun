// sysrun.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#pragma comment(lib, "wtsapi32")

int Usage() {
	printf("Usage: sysrun <executable> [arguments]*\n");
	return 1;
}

BOOL IsSystemSid(PSID sid) {
	return ::IsWellKnownSid(sid, WinLocalSystemSid);
}

// find first SYSTEM process with a good token to use

HANDLE OpenSystemProcessToken() {
	PWTS_PROCESS_INFO pInfo;
	DWORD count;
	if (!::WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pInfo, &count)) {
		printf("Error enumerating processes (are you running elevated?) (error=%d)\n", ::GetLastError());
		return nullptr;
	}

	HANDLE hToken{};
	for (DWORD i = 0; i < count && !hToken; i++) {
		if (pInfo[i].SessionId == 0 && IsSystemSid(pInfo[i].pUserSid)) {
			auto hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pInfo[i].ProcessId);
			if (hProcess) {
				::OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken);
				::CloseHandle(hProcess);
			}
		}
	}

	::WTSFreeMemory(pInfo);
	return hToken;
}

BOOL SetPrivilege(HANDLE hToken, PCTSTR lpszPrivilege, bool bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!::LookupPrivilegeValue(nullptr, lpszPrivilege, &luid))
		return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		return FALSE;
	}

	if (::GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

BOOL EnableDebugPrivilege(void) {
	HANDLE hToken;
	BOOL result;
	if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return FALSE;
	}
	result = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	::CloseHandle(hToken);
	return result;
}

int wmain(int argc, const wchar_t* argv[]) {
	if (argc < 2)
		return Usage();

	if (FALSE == EnableDebugPrivilege()) {
		printf("EnableDebugPrivilege failed: Access denied (are you running elevated?)\n");
		return 1;
	}

	auto hToken = OpenSystemProcessToken();
	if (!hToken) {
		printf("OpenSystemProcessToken failed: Access denied (are you running elevated?)\n");
		return 1;
	}

	HANDLE hDupToken, hPrimary;
	::DuplicateTokenEx(hToken, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES, 
		nullptr, SecurityImpersonation, TokenImpersonation, &hDupToken);
	::DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hPrimary);
	::CloseHandle(hToken);

	if (hDupToken == nullptr) {
		printf("Failed to create token (are you running elevated?) (error=%d)\n", ::GetLastError());
		return 1;
	}

	using namespace std;

	wstring commandLine;
	for (int i = 1; i < argc; i++)
		(commandLine += argv[i]) += L" ";

	STARTUPINFO si = { sizeof(si) };
	si.lpDesktop = L"Winsta0\\default";

	PROCESS_INFORMATION pi;

	BOOL impersonated = ::SetThreadToken(nullptr, hDupToken);
	assert(impersonated);
	if (!impersonated) {
		printf("SetThreadToken failed: Access denied (are you running elevated?)\n");
		return 1;
	}

	HANDLE hCurrentToken;
	DWORD session = 0, len = sizeof(session);
	::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrentToken);
	::GetTokenInformation(hCurrentToken, TokenSessionId, &session, len, &len);
	::CloseHandle(hCurrentToken);

	if (!SetPrivilege(hDupToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE) ||
		!SetPrivilege(hDupToken, SE_DEBUG_NAME, TRUE) ||
		!SetPrivilege(hDupToken, SE_INCREASE_QUOTA_NAME, TRUE)) {
		printf("SetPrivilege failed: Insufficient privileges\n");
		return 1;
	}

	BOOL ok = ::SetTokenInformation(hPrimary, TokenSessionId, &session, sizeof(session));

	if (!::CreateProcessAsUser(hPrimary, nullptr, const_cast<wchar_t*>(commandLine.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
		printf("Failed to create process (error=%d)\n", ::GetLastError());
	}
	else {
		printf("Process created: %d\n", pi.dwProcessId);
	}

	return 0;
}

