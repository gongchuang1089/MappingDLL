#pragma once
#include <Windows.h>
#include <iostream>

namespace HookBypass
{
	void LoadLib();
	bool UnHookMethod(const char* MethodName, const wchar_t* dllName, PBYTE saveBuf, HANDLE hProc = nullptr);
	bool ReHookMethod(const char* MethodName, const wchar_t* dllName, PBYTE saveBuf, HANDLE hProc = nullptr);
	bool Bypass(bool AbleAll, HANDLE hProc = nullptr);
	bool ReBypass(bool AbleAll, HANDLE hProc = nullptr);
	bool ApplyHookBypass(bool disableHooks, HANDLE hproc = nullptr);
	bool ReHookBypass(bool disableHooks, HANDLE hproc = nullptr);
}