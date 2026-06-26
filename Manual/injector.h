#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>
#include <winternl.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFileName);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif  // _WIN64

typedef DWORD(WINAPI* PfnZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG CreateThreadFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximunStackSize,
    LPVOID pUnkown);


struct MANUAL_MAPPING_DATA
{
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif // _WIN64
    BYTE* pBase;
    HINSTANCE hMod;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
    BOOL SEHSupport;

#ifdef _WIN64
    void* pCxxThrowStub;
#endif // _WIN64

};
bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize,DWORD pid, bool ClearHeader = true, bool ClearNonNeededSections = true, bool AdjustProtections = true, bool SEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
