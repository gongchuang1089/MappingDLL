#include "injector.h"


#if defined(DISABLE_OUTPUT)
#define ILog(text, ...) do {} while (0)
#else
#define ILog(text, ...) do { printf(text, ##__VA_ARGS__); } while (0)
#endif // DISABLE_OUTPUT


#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif // _WIN64

#define MEM_SET (MEM_COMMIT | MEM_RESERVE)
bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize,DWORD pid, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved)
{
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
	{
		ILog("Invaild file");
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldFileHeader = &pOldNtHeader->FileHeader;
	pOldOptHeader = &pOldNtHeader->OptionalHeader;

	if (pOldFileHeader->Machine != CURRENT_ARCH)
	{
		ILog("Invalid platform\n");
		return false;
	}

	ILog("File ok\n");

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		return false;
	}

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_SET, PAGE_READWRITE));
	if (!pTargetBase)
	{
		ILog("Target process memory allocation failed (ex) 0x%X\n", GetLastError());
		return false;
	}
	DWORD oldp = 0;
	if (!VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp))
	{
		ILog("Can't protect 0x%X\n", GetLastError());
	}

	MANUAL_MAPPING_DATA data = { 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;

#ifdef _WIN64 
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
	SEHExceptionSupport = false;
#endif // 
	data.pBase = pTargetBase;
	data.fdwReasonParam = fdwReason;
	data.reservedParam = lpReserved;
	data.SEHSupport = SEHExceptionSupport;

#ifdef _WIN64
	data.pCxxThrowStub = nullptr;
	if (SEHExceptionSupport)
	{
		HMODULE hk32 = GetModuleHandleW(L"kernel32.dll");
		FARPROC pRaiseEx = hk32 ? GetProcAddress(hk32, "RaiseException") : nullptr;
		void* stubMem = pRaiseEx
			? VirtualAllocEx(hProc, nullptr, 0x1000, MEM_SET, PAGE_EXECUTE_READWRITE)
			: nullptr;
		if (!stubMem)
		{
			ILog("WARNING: couldn't allocate CxxThrow stub; typed catches may fail\n");
		}
		else
		{
			BYTE blob[0x200] = {};
			BYTE stub[] = {
				0x48, 0x83, 0xEC, 0x48,                                  // sub  rsp, 0x48
				0xC7, 0x44, 0x24, 0x20, 0x20, 0x05, 0x93, 0x19,          // mov  [rsp+0x20], 0x19930520 (EH_MAGIC_NUMBER1)
				0xC7, 0x44, 0x24, 0x24, 0x00, 0x00, 0x00, 0x00,          // mov  [rsp+0x24], 0
				0x48, 0x89, 0x4C, 0x24, 0x28,                            // mov  [rsp+0x28], rcx ; obj
				0x48, 0x89, 0x54, 0x24, 0x30,                            // mov  [rsp+0x30], rdx ; ThrowInfo
				0x48, 0xB8, 0,0,0,0,0,0,0,0,                             // movabs rax, IMAGE_BASE  (patched at offset 32)
				0x48, 0x89, 0x44, 0x24, 0x38,                            // mov  [rsp+0x38], rax  ; param[3]
				0xB9, 0x63, 0x73, 0x6D, 0xE0,                            // mov  ecx, 0xE06D7363
				0xBA, 0x01, 0x00, 0x00, 0x00,                            // mov  edx, 1 (NONCONTINUABLE)
				0x41, 0xB8, 0x04, 0x00, 0x00, 0x00,                      // mov  r8d, 4
				0x4C, 0x8D, 0x4C, 0x24, 0x20,                            // lea  r9, [rsp+0x20]
				0x48, 0xB8, 0,0,0,0,0,0,0,0,                             // movabs rax, RaiseException (patched at offset 68)
				0xFF, 0xD0,                                              // call rax
				0xCC,                                                    // int3 (never reached)
			};
			ULONG_PTR imageBase = (ULONG_PTR)pTargetBase;
			ULONG_PTR raiseExceptionAddr = (ULONG_PTR)pRaiseEx;
			memcpy(blob + 32, &imageBase, 8);
			memcpy(blob + 68, &raiseExceptionAddr, 8);
			memcpy(blob, stub, sizeof(stub));


			// UNWIND_INFO at offset 0x80:
			//   Version=1 Flags=0 | SizeOfProlog=4 | CountOfCodes=1 | FrameRegister=0
			//   UnwindCode: { CodeOffset=4, UnwindOp=UWOP_ALLOC_SMALL(2), OpInfo=(0x48/8)-1=8 }
			blob[0x80] = 0x01;        // Version 1, flags 0
			blob[0x81] = 0x04;        // SizeOfProlog (sub rsp, 0x48 is 4 bytes)
			blob[0x82] = 0x01;        // CountOfCodes
			blob[0x83] = 0x00;        // FrameRegister/FrameOffset
			blob[0x84] = 0x04;        // CodeOffset
			blob[0x85] = 0x82;        // (OpInfo=8 << 4) | UWOP_ALLOC_SMALL(2)

			// RUNTIME_FUNCTION at offset 0xA0: { BeginAddr, EndAddr, UnwindData } as RVAs from stubMem.
			DWORD beginAddr = 0;
			DWORD endAddr = (DWORD)sizeof(stub);
			DWORD unwindRva = 0x80;
			memcpy(blob + 0xA0, &beginAddr, 4);
			memcpy(blob + 0xA4, &endAddr, 4);
			memcpy(blob + 0xA8, &unwindRva, 4);

			if (WriteProcessMemory(hProc, stubMem, blob, sizeof(blob), nullptr)) {
				data.pCxxThrowStub = stubMem;
			}
			else {
				ILog("WARNING: couldn't write CxxThrow stub\n");
			}
		}
	}
#endif // _WIN64
	DWORD dwHeaderSize = pOldOptHeader->SizeOfHeaders;
	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, dwHeaderSize, nullptr))
	{
		ILog("Can't write file header 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				ILog("Can't map sections: 0x%x\n", GetLastError());
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_SET, PAGE_READWRITE));
	if (!MappingDataAlloc)
	{
		ILog("Target process mapping allocation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		ILog("Can't write mapping 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	void* pShellCode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_SET, PAGE_READWRITE);
	if (!pShellCode)
	{
		ILog("Memory shellcode allocation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	DWORD dwOld = 0;
	VirtualProtectEx(hProc, pShellCode, 0x1000, PAGE_EXECUTE_READ, &dwOld);

	if (!WriteProcessMemory(hProc, pShellCode, Shellcode, 0x1000, nullptr))
	{
		ILog("Cant't write shellcode 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
		return false;
	}

	ILog("Mapping dll at %p\n", pTargetBase);
	ILog("Mapping Info at %p\n", MappingDataAlloc);
	ILog("Shell code at %p\n", pShellCode);

	ILog("Data allocated\n");

#ifdef _DEBUG
	ILog("My shell code pointer %p\n", Shellcode);
	ILog("Target point %p\n", pShellCode);
	system("pause");
#endif // _DEBUG


	/*PfnZwCreateThreadEx CreateThreadEx = NULL;

	CreateThreadEx = (PfnZwCreateThreadEx)GetProcAddress(hNtdll, "ZwCreateThreadEx");

	if (!CreateThreadEx)
	{
		ILog("Not found createthreadex");
		return false;
	}
	NTSTATUS status;

	HANDLE hRemoteThread = NULL;
	status = CreateThreadEx(
		&hRemoteThread,        // 出参：线程句柄
		THREAD_ALL_ACCESS,     // 线程权限
		NULL,                  // 对象属性
		hProc,                 // 目标进程句柄
		(LPTHREAD_START_ROUTINE)pShellCode, // 入口
		MappingDataAlloc,      // 线程参数
		0,                     // 创建标志，同上面 0
		0,                     // ZeroBits
		0,                     // 栈大小 0 = 默认，同上面 0
		0,                     // 最大栈大小
		NULL                   // 保留参数
	);

	//HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode), MappingDataAlloc,0, nullptr);
	//if (!hThread)
	//{
		//ILog("Thread creation failed 0x%X\n", GetLastError());
		//VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		//VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		//VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
		//return false;
	//}
	//CloseHandle(hThread);
	if (!NT_SUCCESS(status))
	{
		ILog("Thread creation failed 0x%X\n", status);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hRemoteThread);
	*/
	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(te);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot error!:%d\n", GetLastError());
		return FALSE;
	}
	DWORD dwRet = 0;
	HANDLE hThread = NULL;
	if (Thread32First(hSnap, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {   
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);  
				if (hThread) {
					dwRet = QueueUserAPC((PAPCFUNC)Shellcode, hThread,
						(ULONG_PTR)MappingDataAlloc); 
					hThread = NULL;
				}
			}
		} while (Thread32Next(hSnap, &te)); 
	}
	
	CloseHandle(hThread);
	CloseHandle(hSnap);

	ILog("Theard created at: %p wating for return...\n", pShellCode);

	HINSTANCE hCheck = NULL;
	DWORD tStart = GetTickCount();
	const DWORD TimeOutMs = 30000;
	while (!hCheck)
	{
		DWORD ExitCode = 0;
		GetExitCodeProcess(hProc, &ExitCode);
		if (ExitCode != STILL_ACTIVE)
		{
			ILog("Process crashed,eixt code: 0x%X\n", ExitCode);
			return false;
		}

		if (GetTickCount() - tStart > TimeOutMs)
		{
			ILog("Injection timed out after %u ms (DllMain may be hung)\n", TimeOutMs);
			return false;
		}

		MANUAL_MAPPING_DATA data_checked = { 0 };
		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(MANUAL_MAPPING_DATA), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			ILog("Wrong mapping ptr\n");
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
			return false;
		}
		else if (hCheck == (HINSTANCE)0x505050) {
			ILog("WARNING: Exception support failed!\n");
		}

		Sleep(10);
	}

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (emptyBuffer == nullptr)
	{
		ILog("Unable to allocate memory\n");
		return false;
	}

	memset(emptyBuffer, 0, 1024 * 1024 * 20);

	DWORD Headerofsize = pOldOptHeader->SizeOfHeaders;

	if (ClearHeader)
	{
		if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, Headerofsize, nullptr))
		{
			ILog("Waring can't clean pe header\n");
		}
	}

	if (ClearNonNeededSections)
	{
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		{
			if (pSectionHeader->Misc.VirtualSize)
			{
				if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) || strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 || strcmp((char*)pSectionHeader->Name, ".reloc") == 0)
				{
					ILog("Processing %s removal\n", pSectionHeader->Name);
					if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr))
					{
						ILog("Can't clear section %s: 0x%x\n", pSectionHeader->Name, GetLastError());
					}
				}
			}
		}
	}

	if (AdjustProtections)
	{
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		{
			DWORD old = 0;
			DWORD newP = PAGE_READONLY;

			if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
			{
				newP = PAGE_READWRITE;
			}
			else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			{
				newP = PAGE_EXECUTE_READ;
			}
			if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
				ILog("section %s set as %lX\n", (char*)pSectionHeader->Name, newP);
			}
			else {
				ILog("FAIL: section %s not set as %lX\n", (char*)pSectionHeader->Name, newP);
			}
		}
		DWORD old = 0;
		VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
	}

	if (!WriteProcessMemory(hProc, pShellCode, emptyBuffer, 0x1000, nullptr)) {
		ILog("WARNING: Can't clear shellcode\n");
	}
	if (!VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE)) {
		ILog("WARNING: can't release shell code memory\n");
	}
	if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
		ILog("WARNING: can't release mapping data memory\n");
	}

	free(emptyBuffer);
	emptyBuffer = nullptr;

	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )

void _stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
	{
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pBase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	//重定位
	BYTE* LocationDelta = pBase - pOpt->ImageBase;

	if (LocationDelta)
	{
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
			{
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
				{
					if (RELOC_FLAG(*pRelativeInfo))
					{
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			if (!hDll)
			{
				return;
			}
			ULONG_PTR* pThunckRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
			{
				pThunckRef = pFuncRef;
			}
			for (;*pThunckRef;++pThunckRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunckRef))
				{
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunckRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunckRef));
#ifdef _WIN64
					// Detect "_CxxThrowException" by name (char-by-char to avoid
					// referencing string literals from the injector's .rdata).
					const char* n = pImport->Name;
					bool isCxxThrow =
						pData->pCxxThrowStub &&
						n[0] == '_' && n[1] == 'C' && n[2] == 'x' && n[3] == 'x' &&
						n[4] == 'T' && n[5] == 'h' && n[6] == 'r' && n[7] == 'o' &&
						n[8] == 'w' && n[9] == 'E' && n[10] == 'x' && n[11] == 'c' &&
						n[12] == 'e' && n[13] == 'p' && n[14] == 't' && n[15] == 'i' &&
						n[16] == 'o' && n[17] == 'n' && n[18] == '\0';
					if (isCxxThrow) {
						*pFuncRef = (ULONG_PTR)pData->pCxxThrowStub;
					}
					else
#endif
					{
						*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
					}
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64

	if (pData->SEHSupport)
	{
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size)
		{
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase))
			{
				ExceptionSupportFailed = true;
			}
		}

		// Register the CxxThrow stub's own RUNTIME_FUNCTION so the OS unwinder
		// can walk through it on its way back to the throw site's frame.
		if (pData->pCxxThrowStub)
		{
			BYTE* stubBase = static_cast<BYTE*>(pData->pCxxThrowStub);
			_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(stubBase + 0xA0),
				1, (DWORD64)stubBase);
		}
	}

#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}