#include"HookBypass.h"

void HookBypass::LoadLib()
{
	if (!GetModuleHandleW(L"kernel32"))
	{
		LoadLibraryW(L"kernel32");
	}

	/*if (!GetModuleHandleW(L"kernelBase"))
	{
		LoadLibraryW(L"kernelBase");
	}*/
}

enum MemApiNum {
	VIRTUALALLOCEX = 1,
	VIRTUALPROTECTEX = 2,
	VIRTUALFREEEX = 3,
	LOADLIBRARYA = 4,

	/*VIRTUALALLOCEX_BASE = 5,
	VIRTUALPROTECTEX_BASE = 6,
	VIRTUALFREEEX_BASE = 7,
	LOADLIBRARYA_BASE = 8,*/
};
BYTE originalHookBytes[10][6];


bool HookBypass::UnHookMethod(const char* MethodName, const wchar_t* dllName, PBYTE saveBuf, HANDLE hProc)
{
	HMODULE hModule = GetModuleHandleW(dllName);
	if (!hModule)
	{
		std::wcout << L"Error: GetModuleHandleW failed for:" << dllName << L"(" << GetLastError() << L")" << std::endl;
		return false;
	}

	LPVOID MethodAddress = GetProcAddress(hModule, MethodName);
	if (!MethodAddress)
	{
		std::wcout << L"Error: GetProcAddress failed for:" << MethodName << L"in" << dllName << L":" << GetLastError() << std::endl;
		return false;
	}
	if (hProc == nullptr || hProc == INVALID_HANDLE_VALUE)
	{
		std::cout << "hProc is null" << std::endl;
		return false;
	}

	PBYTE originalGameBytes[6];
	if (!ReadProcessMemory(hProc, MethodAddress, originalGameBytes, sizeof(char) * 6, NULL))
	{
		std::wcout << L"Error: ReadProcessMemory failed for:" << MethodName << L"in" << dllName << L":" << GetLastError() << std::endl;
		return false;
	}

	if (saveBuf != nullptr)
	{
		memcpy(saveBuf, originalGameBytes, sizeof(char) * 6);
	}

	PBYTE originalDllBytes[6];
	memcpy(originalDllBytes, MethodAddress, sizeof(char) * 6);
	if (!WriteProcessMemory(hProc, MethodAddress, originalDllBytes, sizeof(char) * 6, NULL))
	{
		std::wcout << L"Error: WriteProcessMemory failed for" << MethodName << L"in" << dllName << L":" << GetLastError() << std::endl;
		return false;
	}
	return true;
}

bool HookBypass::ReHookMethod(const char* MethodName, const wchar_t* dllName, PBYTE saveBuf, HANDLE hProc)
{
	HMODULE hModule = GetModuleHandleW(dllName);
	if (!hModule)
	{
		std::wcout << L"Error: GetModuleHandleW failed for:" << dllName << L"(" << GetLastError() << L")" << std::endl;
		return false;
	}

	LPVOID MethodAddress = GetProcAddress(hModule, MethodName);
	if (!MethodAddress)
	{
		std::wcout << L"Error: GetProcAddress failed for:" << MethodName << L"in" << dllName << L":" << GetLastError() << std::endl;
		return false;
	}
	if (hProc == nullptr || hProc == INVALID_HANDLE_VALUE)
	{
		std::cout << "hProc is null" << std::endl;
		return false;
	}

	if (!WriteProcessMemory(hProc, MethodAddress, saveBuf, sizeof(char) * 6, NULL))
	{
		std::wcout << L"Error: WriteProcessMemory failed for" << MethodName << L"in" << dllName << L":" << GetLastError() << std::endl;
		return false;
	}
	return true;
}

bool HookBypass::Bypass(bool AbleAll, HANDLE hProc)
{
	bool res = true;
	if (AbleAll)
	{
		res &= UnHookMethod("VirtualAllocEx", L"kernel32", originalHookBytes[VIRTUALALLOCEX], hProc);
		res &= UnHookMethod("VirtualProtectEx", L"kernel32", originalHookBytes[VIRTUALPROTECTEX], hProc);
		res &= UnHookMethod("VirtualFreeEx", L"kernel32", originalHookBytes[VIRTUALFREEEX], hProc);
		res &= UnHookMethod("LoadLibraryA", L"kernel32", originalHookBytes[LOADLIBRARYA], hProc);
	}

	return res;
}

bool HookBypass::ReBypass(bool AbleAll, HANDLE hProc)
{
	bool res = true;
	if (AbleAll)
	{
		res &= ReHookMethod("VirtualAllocEx", L"kernel32", originalHookBytes[VIRTUALALLOCEX], hProc);
		res &= ReHookMethod("VirtualProtectEx", L"kernel32", originalHookBytes[VIRTUALPROTECTEX], hProc);
		res &= ReHookMethod("VirtualFreeEx", L"kernel32", originalHookBytes[VIRTUALFREEEX], hProc);
		res &= ReHookMethod("LoadLibraryA", L"kernel32", originalHookBytes[LOADLIBRARYA], hProc);
	}

	return res;
}


bool HookBypass::ApplyHookBypass(bool disableHooks, HANDLE hproc)
{
	if (Bypass(disableHooks, hproc)==false)
	{
		std::cout << "Failed to bypass VAC hooks!" << std::endl;
		if (disableHooks)
		{
			if (ReBypass(disableHooks, hproc)==false)
			{
				std::cout << "Failed to restore VAC hooks.  This is VERY dangerous." << std::endl;
			}
			return false;
		}
		if (disableHooks)
		{
			std::cout << "[+] VAC hooks bypassed." << std::endl;
			return true;
		}
		else
		{
			std::cout << "[+] VAC bypass not applied as the target process is steam." << std::endl;
			return false;
		}
		return false;
	}
}

bool HookBypass::ReHookBypass(bool disableHooks, HANDLE hproc)
{
	if (ReBypass(disableHooks, hproc)==false)
	{
		std::cout << "Warning: Failed to restore VAC hooks! This may result in a VAC ban." << std::endl;
		return false;
	}

	else {
		std::cout << "[+] VAC hooks restored." << std::endl;
		return true;
	}
}