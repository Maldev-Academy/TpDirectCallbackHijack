// Copyright 2026 MalDev Academy
// TpDirectCallbackHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/TpDirectCallbackHijack
// 
// NtdllRvaCheck - Creates throwaway local TP_IO, TP_ALPC, and TP_JOB objects in this process; reads the
// VFuncs / Direct.Callback pointers out of each live object; subtracts ntdll's module base;
// and prints the full set of RVAs used by TpDirectCallbackHijack's pool walker.
//
// This logic can be merged with TpDirectCallbackHijack so that it doesn't rely on hardcoded RVA
// constants. However it is separated to keep the injector binary lean, with no named-pipe
// IoC, no ntdll internal-API imports, and no CreateNamedPipeW / CreateThreadpoolIo /
// NtAlpcCreatePort / TpAllocAlpcCompletion / TpAllocJobNotification exports in the
// injector's IAT.

#include <Windows.h>
#include <Psapi.h>
#include <threadpoolapiset.h>
#include <stdio.h>

#include "..\TpDirectCallbackHijack\InternalStructures.h"
#include "..\TpDirectCallbackHijack\Structures.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Undocumented ntdll types 
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// https://ntdoc.m417z.com/alpc_port_attributes
typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;


typedef NTSTATUS (NTAPI *fnNtAlpcCreatePort)(
    PHANDLE                     PortHandle,
    POBJECT_ATTRIBUTES          ObjectAttributes,
    PALPC_PORT_ATTRIBUTES       PortAttributes);

typedef VOID (NTAPI *PTP_ALPC_CALLBACK)(
    PTP_CALLBACK_INSTANCE       Instance,
    PVOID                       Context,
    PVOID                       Alpc);

typedef NTSTATUS (NTAPI *fnTpAllocAlpcCompletion)(
    PVOID*                      OutAlpc,
    HANDLE                      hAlpcPort,
    PTP_ALPC_CALLBACK           Callback,
    PVOID                       Context,
    PTP_CALLBACK_ENVIRON        CallbackEnviron);

typedef VOID (NTAPI *PTP_JOB_CALLBACK)(
    PTP_CALLBACK_INSTANCE       Instance,
    PVOID                       Context,
    HANDLE                      Job,
    ULONG                       JobNotification,
    ULONG_PTR                   Data);

typedef NTSTATUS (NTAPI *fnTpAllocJobNotification)(
    PVOID*                      OutJob,
    HANDLE                      hJob,
    PTP_JOB_CALLBACK            Callback,
    PVOID                       Context,
    PTP_CALLBACK_ENVIRON        CallbackEnviron);


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Dummy callbacks - the pool never dispatches these, we only need the allocators
// to produce live objects we can read fields out of.
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static VOID CALLBACK DummyIoCallback(
    PTP_CALLBACK_INSTANCE   Instance,
    PVOID                   Context,
    PVOID                   Overlapped,
    ULONG                   IoResult,
    ULONG_PTR               NumberOfBytesTransferred,
    PTP_IO                  Io)
{
    (VOID)Instance; (VOID)Context; (VOID)Overlapped;
    (VOID)IoResult; (VOID)NumberOfBytesTransferred; (VOID)Io;
}

static VOID NTAPI DummyAlpcCallback(
    PTP_CALLBACK_INSTANCE   Instance,
    PVOID                   Context,
    PVOID                   Alpc)
{
    (VOID)Instance; (VOID)Context; (VOID)Alpc;
}

static VOID NTAPI DummyJobCallback(
    PTP_CALLBACK_INSTANCE   Instance,
    PVOID                   Context,
    HANDLE                  Job,
    ULONG                   Notification,
    ULONG_PTR               Data)
{
    (VOID)Instance; (VOID)Context; (VOID)Job;
    (VOID)Notification; (VOID)Data;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Local allocators - one per TP_<kind>. Each returns an opaque pointer we cast to the
// matching struct in InternalStructures.h for field access.
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CreateLocalTpIo(OUT PHANDLE phPipe, OUT PTP_IO* ppIo)
{
    HANDLE  hPipe       = INVALID_HANDLE_VALUE;
    PTP_IO  pIo         = NULL;
    WCHAR   wszPipe[64] = { 0 };

    *phPipe = INVALID_HANDLE_VALUE;
    *ppIo   = NULL;

    (VOID)swprintf_s(wszPipe, _countof(wszPipe), L"\\\\.\\pipe\\ntdll_rva_check_%lu_%lu",
        GetCurrentProcessId(), GetTickCount());

    hPipe = CreateNamedPipeW(wszPipe,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        0x01, 0x100, 0x100, 0x00, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateNamedPipeW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if ((pIo = CreateThreadpoolIo(hPipe, DummyIoCallback, NULL, NULL)) == NULL)
    {
        printf("[!] CreateThreadpoolIo Failed With Error: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return FALSE;
    }

    *phPipe = hPipe;
    *ppIo   = pIo;
    return TRUE;
}

static BOOL CreateLocalTpAlpc(IN HMODULE hNtdll, OUT PHANDLE phPort, OUT PVOID* ppAlpc)
{
    fnNtAlpcCreatePort      pNtAlpcCreatePort       = NULL;
    fnTpAllocAlpcCompletion pTpAllocAlpcCompletion  = NULL;
    HANDLE                  hPort                   = NULL;
    PVOID                   pAlpc                   = NULL;
    ALPC_PORT_ATTRIBUTES    alpcPortAttr            = { 0 };
    TP_CALLBACK_ENVIRON     TpCallbackEnviron       = { 0 };
    NTSTATUS                ntStatus                = 0x00;

    *phPort = NULL;
    *ppAlpc = NULL;

    pNtAlpcCreatePort      = (fnNtAlpcCreatePort)      GetProcAddress(hNtdll, "NtAlpcCreatePort");
    pTpAllocAlpcCompletion = (fnTpAllocAlpcCompletion) GetProcAddress(hNtdll, "TpAllocAlpcCompletion");

    if (!pNtAlpcCreatePort || !pTpAllocAlpcCompletion)
    {
        printf("[!] GetProcAddress Failed With Error: %lu\n", GetLastError());
        printf("[i] NtAlpcCreatePort=%p TpAllocAlpcCompletion=%p\n", (PVOID)pNtAlpcCreatePort, (PVOID)pTpAllocAlpcCompletion);
        return FALSE;
    }

    alpcPortAttr.MaxMessageLength = 0x1000;

    if (!NT_SUCCESS((ntStatus = pNtAlpcCreatePort(&hPort, NULL, &alpcPortAttr))) || !hPort)
    {
        printf("[!] NtAlpcCreatePort Failed With Status: 0x%08X\n", (ULONG)ntStatus);
        return FALSE;
    }

    InitializeThreadpoolEnvironment(&TpCallbackEnviron);

    if (!NT_SUCCESS((ntStatus = pTpAllocAlpcCompletion(&pAlpc, hPort, DummyAlpcCallback, NULL, &TpCallbackEnviron))) || !pAlpc)
    {
        printf("[!] TpAllocAlpcCompletion Failed With Status: 0x%08X\n", (ULONG)ntStatus);
        CloseHandle(hPort);
        return FALSE;
    }

    *phPort = hPort;
    *ppAlpc = pAlpc;
    return TRUE;
}

static BOOL CreateLocalTpJob(IN HMODULE hNtdll, OUT PHANDLE phJob, OUT PVOID* ppJob)
{
    fnTpAllocJobNotification pTpAllocJobNotification    = NULL;
    HANDLE                   hJob                       = NULL;
    PVOID                    pJob                       = NULL;
    TP_CALLBACK_ENVIRON      TpCallbackEnviron          = { 0 };
    NTSTATUS                 ntStatus                   = 0x00;

    *phJob = NULL;
    *ppJob = NULL;

    if (!(pTpAllocJobNotification = (fnTpAllocJobNotification)GetProcAddress(hNtdll, "TpAllocJobNotification")))
    {
        printf("[!] GetProcAddress Failed With Error: %lu\n", GetLastError());
        printf("[i] TpAllocJobNotification=%p \n", (PVOID)pTpAllocJobNotification);
        return FALSE;
    }

    if (!(hJob = CreateJobObjectW(NULL, NULL)))
    {
        printf("[!] CreateJobObjectW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    InitializeThreadpoolEnvironment(&TpCallbackEnviron);

    ntStatus = pTpAllocJobNotification(&pJob, hJob, DummyJobCallback, NULL, &TpCallbackEnviron);
    if (!NT_SUCCESS(ntStatus) || !pJob)
    {
        printf("[!] TpAllocJobNotification Failed With Status: 0x%08X\n", (ULONG)ntStatus);
        CloseHandle(hJob);
        return FALSE;
    }

    *phJob = hJob;
    *ppJob = pJob;
    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Reads a field pointer out of a live TP_<kind> object, subtracts ntdll base, and
// returns the RVA. Sanity-checks that the field pointer actually lies inside ntdll
static BOOL DeriveRva(IN PBYTE pNtdllBase, IN ULONG uNtdllSize, IN PVOID pFieldPtr, IN LPCSTR pszName, OUT PULONG puRva)
{
    ULONGLONG uDelta = 0;

    *puRva = 0;

    if (!pFieldPtr)
    {
        printf("[!] %s: Field Pointer is NULL\n", pszName);
        return FALSE;
    }

    uDelta = (ULONGLONG)((PBYTE)pFieldPtr - pNtdllBase);
    if (uDelta >= uNtdllSize)
    {
        printf("[!] %s: Field Pointer 0x%p is Outside NTDLL [Base=0x%p, Size=0x%lX]\n",
            pszName, pFieldPtr, (PVOID)pNtdllBase, uNtdllSize);
        return FALSE;
    }

    *puRva = (ULONG)uDelta;
    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int main()
{
    HMODULE     hNtdll              = NULL;
    MODULEINFO  ModuleInfo          = { 0 };
    PBYTE       pNtdllBase          = NULL;
    ULONG       uNtdllSize          = 0;

    HANDLE      hPipe               = INVALID_HANDLE_VALUE;
    PTP_IO      pIo                 = NULL;
    HANDLE      hAlpcPort           = NULL;
    PVOID       pAlpc               = NULL;
    HANDLE      hJob                = NULL;
    PVOID       pJob                = NULL;

    ULONG       uRvaIopCgm          = 0,
                uRvaIopExec         = 0;
    ULONG       uRvaAlpcpCgm        = 0,
                uRvaAlpcpExec       = 0;
    ULONG       uRvaJobpCgm         = 0,
                uRvaJobpExec        = 0;

    int         iExitCode           = -1;

    if (!(hNtdll = GetModuleHandle(TEXT("NTDLL"))))
    {
        printf("[!] GetModuleHandle Failed With Error: %lu\n", GetLastError());
        return -1;
    }
    if (!GetModuleInformation(GetCurrentProcess(), hNtdll, &ModuleInfo, sizeof(ModuleInfo)))
    {
        printf("[!] GetModuleInformation Failed With Error: %lu\n", GetLastError());
        return -1;
    }

    pNtdllBase = (PBYTE)ModuleInfo.lpBaseOfDll;
    uNtdllSize = (ULONG)ModuleInfo.SizeOfImage;

    // ---------- TP_IO ----------
    if (!CreateLocalTpIo(&hPipe, &pIo))
        goto _END_OF_FUNC;

    printf("[i] Local TP_IO           : 0x%p\n", (PVOID)pIo);

    if (!DeriveRva(pNtdllBase, uNtdllSize, ((TP_IO*)pIo)->CleanupGroupMember.VFuncs, "TP_IO.CleanupGroupMember.VFuncs", &uRvaIopCgm))
        goto _END_OF_FUNC;
    if (!DeriveRva(pNtdllBase, uNtdllSize, ((TP_IO*)pIo)->Direct.Callback,           "TP_IO.Direct.Callback",           &uRvaIopExec))
        goto _END_OF_FUNC;

    // ---------- TP_ALPC ----------
    if (!CreateLocalTpAlpc(hNtdll, &hAlpcPort, &pAlpc))
        goto _END_OF_FUNC;

    printf("[i] Local TP_ALPC         : 0x%p\n", pAlpc);

    if (!DeriveRva(pNtdllBase, uNtdllSize, ((TP_ALPC*)pAlpc)->CleanupGroupMember.VFuncs, "TP_ALPC.CleanupGroupMember.VFuncs", &uRvaAlpcpCgm))
        goto _END_OF_FUNC;
    if (!DeriveRva(pNtdllBase, uNtdllSize, ((TP_ALPC*)pAlpc)->Direct.Callback,           "TP_ALPC.Direct.Callback",           &uRvaAlpcpExec))
        goto _END_OF_FUNC;

    // ---------- TP_JOB ----------
    if (!CreateLocalTpJob(hNtdll, &hJob, &pJob))
        goto _END_OF_FUNC;

    printf("[i] Local TP_JOB          : 0x%p\n\n", pJob);

    if (!DeriveRva(pNtdllBase, uNtdllSize, ((TP_JOB*)pJob)->CleanupGroupMember.VFuncs, "TP_JOB.CleanupGroupMember.VFuncs", &uRvaJobpCgm))
        goto _END_OF_FUNC;
    if (!DeriveRva(pNtdllBase, uNtdllSize, ((TP_JOB*)pJob)->Direct.Callback,           "TP_JOB.Direct.Callback",           &uRvaJobpExec))
        goto _END_OF_FUNC;

    // ---------- Output ----------
    printf("// ===========================================================================\n");
    printf("// Derived at runtime by TPP_PROBE from locally-allocated TP_IO / TP_ALPC / TP_JOB.\n");
    printf("// ===========================================================================\n\n");

    printf("#define TPP_IOP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA     0x%06lX\n",   uRvaIopCgm);
    //printf("#define TPP_IOP_EXECUTE_CALLBACK_RVA                0x%06lX\n\n", uRvaIopExec);

    printf("#define TPP_ALPCP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA   0x%06lX\n",   uRvaAlpcpCgm);
    //printf("#define TPP_ALPCP_EXECUTE_CALLBACK_RVA              0x%06lX\n\n", uRvaAlpcpExec);

    printf("#define TPP_JOBP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA    0x%06lX\n",   uRvaJobpCgm);
    //printf("#define TPP_JOBP_EXECUTE_CALLBACK_RVA               0x%06lX\n",   uRvaJobpExec);
    printf("\n");

    iExitCode = 0;

_END_OF_FUNC:
    if (pIo)                            CloseThreadpoolIo(pIo);
    if (hPipe != INVALID_HANDLE_VALUE)  CloseHandle(hPipe);
    if (hAlpcPort)                      CloseHandle(hAlpcPort);
    if (hJob)                           CloseHandle(hJob);
    return iExitCode;
}


/*
# On Windows build 10.0.26100.9711 (Windows 11 24H2)
# The Output Is:

#define TPP_IOP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA     0x174BE8
#define TPP_IOP_EXECUTE_CALLBACK_RVA                0x088F50            // Not used

#define TPP_ALPCP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA   0x174DD0
#define TPP_ALPCP_EXECUTE_CALLBACK_RVA              0x024150            // Not used

#define TPP_JOBP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA    0x174C08
#define TPP_JOBP_EXECUTE_CALLBACK_RVA               0x0BF5F0            // Not used


# Manually Verified using Windbg:

0:004> ? ntdll!TppIopCleanupGroupMemberVFuncs    - ntdll
Evaluate expression: 1526760 = 00000000`00174be8
0:004> ? ntdll!TppIopExecuteCallback             - ntdll
Evaluate expression: 560976  = 00000000`00088f50

0:004> ? ntdll!TppAlpcpCleanupGroupMemberVFuncs  - ntdll
Evaluate expression: 1527248 = 00000000`00174dd0
0:004> ? ntdll!TppAlpcpExecuteCallback           - ntdll
Evaluate expression: 147792  = 00000000`00024150

0:004> ? ntdll!TppJobpCleanupGroupMemberVFuncs   - ntdll
Evaluate expression: 1526792 = 00000000`00174c08
0:004> ? ntdll!TppJobpExecuteCallback            - ntdll
Evaluate expression: 783856  = 00000000`000bf5f0
*/

