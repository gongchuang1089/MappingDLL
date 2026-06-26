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
    // 1. 目标：找到notepad++.exe 的 PID
    DWORD parentPid = GetPidByName(L"notepad++.exe");
    if (parentPid == 0) {
        printf("请先运行notepad++程序！\n");
        return 1;
    }

    // 2. 打开父进程，获取句柄，需要 PROCESS_CREATE_PROCESS 权限
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (hParent == NULL) return 1;

    // 3. 初始化扩展启动信息结构体
    STARTUPINFOEXA siex = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize;

    // 第一次调用：获取属性列表所需的内存大小
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    siex.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);

    // 第二次调用：正式初始化属性列表
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attributeSize);

    // 4. 更新属性列表：设置父进程属性
    UpdateProcThreadAttribute(
        siex.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(HANDLE),
        NULL,
        NULL
    );

    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // 5. 创建进程
    // 使用 EXTENDED_STARTUPINFO_PRESENT 标志告诉系统我们使用了扩展启动信息
    BOOL success = CreateProcessA(
        "C:\\Windows\\System32\\cmd.exe", // 要启动的程序
        NULL,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &siex.StartupInfo,
        &pi
    );

    if (success) {
        printf("cmd 已启动，PID: %d，伪造父进程 PID: %d\n", pi.dwProcessId, parentPid);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("创建进程失败，错误代码: %d\n", GetLastError());
    }

    // 6. 清理
    DeleteProcThreadAttributeList(siex.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
    CloseHandle(hParent);

    return 0;
}