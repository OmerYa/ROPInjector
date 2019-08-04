#pragma once

#include <Windows.h>
#include "ROPBuffer.h"

BOOL EnableDebugPriv();

DWORD GetPageSize();

ULONGLONG FindPopGadgets(BYTE* Ntdll, BYTE* PopGadgets, size_t PopGadgetsLen);

BOOL FindFunctionAddresses();

void BuildRiteOfPassageRop(ROPBuffer* Rop, ULONGLONG RemoteShellcode, ULONGLONG RemoteShellcodeAddress);
void BuildSimpleRop(ROPBuffer* Rop, ULONGLONG RemoteShellcode, ULONGLONG RemoteShellcodeAddress);


extern ULONGLONG NtYieldExecution;
extern ULONGLONG CreateMutexAddress;
extern ULONGLONG RtlExitUserThreadAddress;
extern ULONGLONG VirtualProtectAddress;
extern ULONGLONG PopGadgets1Address;
extern ULONGLONG PopGadgets2Address;
extern ULONGLONG PopR10GadgetAddress;
