#pragma once

#include "bb.h"
#include "pe.h"
#include <ntstrsafe.h>


PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64);
PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName);
PINJECT_BUFFER BBGetNativeCode(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath);
NTSTATUS BBApcInject(IN PINJECT_BUFFER pUserBuf, IN PEPROCESS pProcess, IN ULONG initRVA, IN PCWCHAR InitArg);

/// <summary>
/// Check if process is terminating
/// </summary>
/// <param name="imageBase">Process</param>
/// <returns>If TRUE - terminating</returns>
BOOLEAN BBCheckProcessTermination(PEPROCESS pProcess)
{
    LARGE_INTEGER zeroTime = { 0 };
    return KeWaitForSingleObject(pProcess, Executive, KernelMode, FALSE, &zeroTime) == STATUS_WAIT_0;
}


/// <summary>
/// Unlink user-mode module from Loader lists
/// </summary>
/// <param name="pProcess">Target process</param>
/// <param name="pBase">Module base</param>
/// <param name="isWow64">If TRUE - unlink from PEB32 Loader, otherwise use PEB64</param>
/// <returns>Status code</returns>
NTSTATUS BBUnlinkFromLoader(IN PEPROCESS pProcess, IN PVOID pBase, IN BOOLEAN isWow64)
{
    UNREFERENCED_PARAMETER(isWow64);
    NTSTATUS status = STATUS_SUCCESS;
    ASSERT(pProcess != NULL);
    if (pProcess == NULL)
        return STATUS_INVALID_PARAMETER;

    // Protect from UserMode AV
    __try
    {
        //// Wow64 process
        //if (isWow64)
        //{
        //    PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
        //    if (pPeb32 == NULL)
        //    {
        //        DPRINT("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
        //        return STATUS_NOT_FOUND;
        //    }

        //    // Search in InLoadOrderModuleList
        //    for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
        //        pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
        //        pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
        //    {
        //        PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

        //        // Unlink
        //        if ((PVOID)pEntry->DllBase == pBase)
        //        {
        //            RemoveEntryList32(&pEntry->InLoadOrderLinks);
        //            RemoveEntryList32(&pEntry->InInitializationOrderLinks);
        //            RemoveEntryList32(&pEntry->InMemoryOrderLinks);
        //            RemoveEntryList32(&pEntry->HashLinks);

        //            break;
        //        }
        //    }
        //}
        // Native process
        
        {
            PPEB pPeb = PsGetProcessPeb(pProcess);
            if (!pPeb)
            {
                DPRINT("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
                return STATUS_NOT_FOUND;
            }

            // Search in InLoadOrderModuleList
            for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
                pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
                pListEntry = pListEntry->Flink)
            {
                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                // Unlink
                if (pEntry->DllBase == pBase)
                {
                    RemoveEntryList(&pEntry->InLoadOrderLinks);
                    RemoveEntryList(&pEntry->InInitializationOrderLinks);
                    RemoveEntryList(&pEntry->InMemoryOrderLinks);
                    RemoveEntryList(&pEntry->HashLinks);

                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("BlackBone: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
    }

    return status;
}


/// <summary>
/// Inject dll into process
/// </summary>
/// <param name="pid">Target PID</param>
/// <param name="pPath">TFull-qualified dll path</param>
/// <returns>Status code</returns>
NTSTATUS BBInjectDll(IN PINJECT_DLL pData)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS pProcess = NULL;

    status = PsLookupProcessByProcessId((HANDLE)pData->pid, &pProcess);
    
    if (NT_SUCCESS(status))
    {
        KAPC_STATE apc;
        UNICODE_STRING ustrPath, ustrNtdll;
        SET_PROC_PROTECTION prot = { 0 };
        PVOID pNtdll = NULL;
        PVOID LdrLoadDll = NULL;
        BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;
        
        // :不注入wow64
        if (isWow64)
        {
            if (pProcess)
                ObDereferenceObject(pProcess);

            return STATUS_PROCESS_IS_PROTECTED;
        }

        // Process in signaled state, abort any operations
        if (BBCheckProcessTermination( PsGetCurrentProcess() ))
        {
            DPRINT("BlackBone: %s: Process %u is terminating. Abort\n", __FUNCTION__, pData->pid);
            if (pProcess)
                ObDereferenceObject(pProcess);

            return STATUS_PROCESS_IS_TERMINATING;
        }

        // Copy mmap image buffer to system space.
        // Buffer will be released in mapping routine automatically

        // 不使用
        /*
        if (pData->type == IT_MMap && pData->imageBase)
        {
            __try
            {
                ProbeForRead((PVOID)pData->imageBase, pData->imageSize, 1);
                systemBuffer = ExAllocatePoolWithTag(PagedPool, pData->imageSize, BB_POOL_TAG);
                RtlCopyMemory(systemBuffer, (PVOID)pData->imageBase, pData->imageSize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DPRINT("BlackBone: %s: AV in user buffer: 0x%p - 0x%p\n", __FUNCTION__,
                    pData->imageBase, pData->imageBase + pData->imageSize);

                if (pProcess)
                    ObDereferenceObject(pProcess);

                return STATUS_INVALID_USER_BUFFER;
            }
        }
        */

        KeStackAttachProcess(pProcess, &apc);

        RtlInitUnicodeString(&ustrPath, pData->FullDllPath);
        RtlInitUnicodeString(&ustrNtdll, L"Ntdll.dll");

        // Handle manual map separately
        if (pData->type == IT_MMap)
        {
            // :不使用
            /*
            MODULE_DATA mod = { 0 };

            __try {
                status = BBMapUserImage(
                    pProcess, &ustrPath, systemBuffer,
                    pData->imageSize, pData->asImage, pData->flags,
                    pData->initRVA, pData->initArg, &mod
                );
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DPRINT("BlackBone: %s: Fatal exception in BBMapUserImage. Exception code 0x%x\n", __FUNCTION__, GetExceptionCode());
            }

            KeUnstackDetachProcess(&apc);

            if (pProcess)
                ObDereferenceObject(pProcess);

            return status;
            */
        }

        // Get ntdll base
        pNtdll = BBGetUserModule(pProcess, &ustrNtdll, isWow64);

        if (!pNtdll)
        {
            DPRINT("BlackBone: %s: Failed to get Ntdll base\n", __FUNCTION__);
            status = STATUS_NOT_FOUND;
        }

        // Get LdrLoadDll address
        if (NT_SUCCESS(status))
        {
            LdrLoadDll = BBGetModuleExport(pNtdll, "LdrLoadDll", pProcess, NULL);
            if (!LdrLoadDll)
            {
                DPRINT("BlackBone: %s: Failed to get LdrLoadDll address\n", __FUNCTION__);
                status = STATUS_NOT_FOUND;
            }
        }

        // :不使用
        // If process is protected - temporarily disable protection
        /*
        if (PsIsProtectedProcess(pProcess))
        {
            prot.pid = pData->pid;
            prot.protection = Policy_Disable;
            prot.dynamicCode = Policy_Disable;
            prot.signature = Policy_Disable;
            BBSetProtection(&prot);
        }
        */

        // Call LdrLoadDll
        if (NT_SUCCESS(status))
        {
            SIZE_T size = 0;
            //PINJECT_BUFFER pUserBuf = isWow64 ? BBGetWow64Code(LdrLoadDll, &ustrPath) : BBGetNativeCode(LdrLoadDll, &ustrPath);

            PINJECT_BUFFER pUserBuf = BBGetNativeCode(LdrLoadDll, &ustrPath);

            // :不使用
            /*
            if (pData->type == IT_Thread)
            {
                status = BBExecuteInNewThread(pUserBuf, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, pData->wait, &threadStatus);

                // Injection failed
                if (!NT_SUCCESS(threadStatus))
                {
                    status = threadStatus;
                    DPRINT("BlackBone: %s: User thread failed with status - 0x%X\n", __FUNCTION__, status);
                }
                // Call Init routine
                else
                {
                    if (pUserBuf->module != 0 && pData->initRVA != 0)
                    {
                        RtlCopyMemory(pUserBuf->buffer, pData->initArg, sizeof(pUserBuf->buffer));
                        BBExecuteInNewThread(
                            (PUCHAR)pUserBuf->module + pData->initRVA,
                            pUserBuf->buffer,
                            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                            TRUE,
                            &threadStatus
                        );
                    }
                    else if (pUserBuf->module == 0)
                        DPRINT("BlackBone: %s: Module base = 0. Aborting\n", __FUNCTION__);
                }
            }
            */
           
            if (pData->type == IT_Apc)
            {
                status = BBApcInject(pUserBuf, pProcess, pData->initRVA, pData->initArg);
            }
            else
            {
                DPRINT("BlackBone: %s: Invalid injection type specified - %d\n", __FUNCTION__, pData->type);
                status = STATUS_INVALID_PARAMETER;
            }

            // Post-inject stuff
            if (NT_SUCCESS(status))
            {
                // Unlink module
                if (pData->unlink)
                    BBUnlinkFromLoader(pProcess, pUserBuf->module, isWow64);

                // Erase header
                if (pData->erasePE)
                {
                    __try
                    {
                        PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(pUserBuf->module);
                        if (pHdr)
                        {
                            ULONG oldProt = 0;
                            size = (pHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ?
                                ((PIMAGE_NT_HEADERS32)pHdr)->OptionalHeader.SizeOfHeaders :
                                pHdr->OptionalHeader.SizeOfHeaders;

                            if (NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), &pUserBuf->module, &size, PAGE_EXECUTE_READWRITE, &oldProt)))
                            {
                                RtlZeroMemory(pUserBuf->module, size);
                                ZwProtectVirtualMemory(ZwCurrentProcess(), &pUserBuf->module, &size, oldProt, &oldProt);

                                DPRINT("BlackBone: %s: PE headers erased. \n", __FUNCTION__);
                            }
                        }
                        else
                            DPRINT("BlackBone: %s: Failed to retrieve PE headers for image\n", __FUNCTION__);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        DPRINT("BlackBone: %s: Exception during PE header erease: 0x%X\n", __FUNCTION__, GetExceptionCode());
                    }
                }
            }

            ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)&pUserBuf, &size, MEM_RELEASE);
        }

        // Restore protection
        /*if (prot.pid != 0)
        {
            prot.protection = Policy_Enable;
            prot.dynamicCode = Policy_Enable;
            prot.signature = Policy_Enable;
            BBSetProtection(&prot);
        }*/

        KeUnstackDetachProcess(&apc);
    }
    else
        DPRINT("BlackBone: %s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);

    if (pProcess)
        ObDereferenceObject(pProcess);

    return status;
}


/// <summary>
/// Check if thread does not satisfy APC requirements
/// </summary>
/// <param name="pThread">Thread to check</param>
/// /// <param name="isWow64">If TRUE - check Wow64 TEB</param>
/// <returns>If TRUE - BBLookupProcessThread should skip thread</returns>
BOOLEAN BBSkipThread(IN PETHREAD pThread, IN BOOLEAN isWow64)
{
    PUCHAR pTeb64 = (PUCHAR)PsGetThreadTeb(pThread);
    
    if (!pTeb64)
        return TRUE;

    // Skip GUI treads. APC to GUI thread causes ZwUserGetMessage to fail
    // TEB64 + 0x78  = Win32ThreadInfo
    if (*(PULONG64)(pTeb64 + 0x78) != 0)
        return TRUE;

    // Skip threads with no ActivationContext
    // Skip threads with no TLS pointer
    if (isWow64)
    {
        PUCHAR pTeb32 = pTeb64 + 0x2000;

        // TEB32 + 0x1A8 = ActivationContextStackPointer
        if (*(PULONG32)(pTeb32 + 0x1A8) == 0)
            return TRUE;

        // TEB64 + 0x2C = ThreadLocalStoragePointer
        if (*(PULONG32)(pTeb32 + 0x2C) == 0)
            return TRUE;
    }
    else
    {
        // TEB64 + 0x2C8 = ActivationContextStackPointer
        if (*(PULONG64)(pTeb64 + 0x2C8) == 0)
            return TRUE;

        // TEB64 + 0x58 = ThreadLocalStoragePointer
        if (*(PULONG64)(pTeb64 + 0x58) == 0)
            return TRUE;
    }

    return FALSE;
}

/// <summary>
/// Find first thread of the target process
/// </summary>
/// <param name="pProcess">Target process</param>
/// <param name="ppThread">Found thread. Thread object reference count is increased by 1</param>
/// <returns>Status code</returns>
NTSTATUS BBLookupProcessThread(IN PEPROCESS pProcess, OUT PETHREAD* ppThread)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE pid = PsGetProcessId(pProcess);
    PVOID pBuf = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, BB_POOL_TAG);
    PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)pBuf;

    ASSERT(ppThread != NULL);
    if (ppThread == NULL)
        return STATUS_INVALID_PARAMETER;

    if (!pInfo)
    {
        DPRINT("BlackBone: %s: Failed to allocate memory for process list\n", __FUNCTION__);
        return STATUS_NO_MEMORY;
    }

    // Get the process thread list
    status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(pBuf, BB_POOL_TAG);
        return status;
    }

    // Find target thread
    if (NT_SUCCESS(status))
    {
        status = STATUS_NOT_FOUND;
        for (;;)
        {
            if (pInfo->UniqueProcessId == pid)
            {
                status = STATUS_SUCCESS;
                break;
            }
            else if (pInfo->NextEntryOffset)
                pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
            else
                break;
        }
    }

    BOOLEAN wow64 = PsGetProcessWow64Process(pProcess) != NULL;

    // Reference target thread
    if (NT_SUCCESS(status))
    {
        status = STATUS_NOT_FOUND;

        // Get first thread
        for (ULONG i = 0; i < pInfo->NumberOfThreads; i++)
        {
            // Skip current thread
            if (/*pInfo->Threads[i].WaitReason == Suspended ||
                 pInfo->Threads[i].ThreadState == 5 ||*/
                pInfo->Threads[i].ClientId.UniqueThread == PsGetCurrentThreadId())
            {
                continue;
            }

            status = PsLookupThreadByThreadId(pInfo->Threads[i].ClientId.UniqueThread, ppThread);

            // Skip specific threads
            if (*ppThread && BBSkipThread(*ppThread, wow64))
            {
                ObDereferenceObject(*ppThread);
                *ppThread = NULL;
                continue;
            }

            break;
        }
    }
    else
        DPRINT("BlackBone: %s: Failed to locate process\n", __FUNCTION__);

    if (pBuf)
        ExFreePoolWithTag(pBuf, BB_POOL_TAG);

    // No suitable thread
    if (!*ppThread)
        status = STATUS_NOT_FOUND;

    return status;
}

VOID KernelApcInjectCallback(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    UNREFERENCED_PARAMETER(NormalContext);

    //DPRINT( "BlackBone: %s: Called. NormalRoutine = 0x%p\n", __FUNCTION__, *NormalRoutine );

    // Skip execution
    if (PsIsThreadTerminating(PsGetCurrentThread()))
        *NormalRoutine = NULL;

    //// Fix Wow64 APC
    //if (PsGetCurrentProcessWow64Process() != NULL)
    //    PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);

    ExFreePoolWithTag(Apc, BB_POOL_TAG);
}


//
// Injection APC routines
//
VOID KernelApcPrepareCallback(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    //DPRINT( "BlackBone: %s: Called\n", __FUNCTION__ );

    // Alert current thread
    KeTestAlertThread(UserMode);
    ExFreePoolWithTag(Apc, BB_POOL_TAG);
}

/// <summary>
/// Queue user-mode APC to the target thread
/// </summary>
/// <param name="pThread">Target thread</param>
/// <param name="pUserFunc">APC function</param>
/// <param name="Arg1">Argument 1</param>
/// <param name="Arg2">Argument 2</param>
/// <param name="Arg3">Argument 3</param>
/// <param name="bForce">If TRUE - force delivery by issuing special kernel APC</param>
/// <returns>Status code</returns>
NTSTATUS BBQueueUserApc(
    IN PETHREAD pThread,
    IN PVOID pUserFunc,
    IN PVOID Arg1,
    IN PVOID Arg2,
    IN PVOID Arg3,
    IN BOOLEAN bForce
)
{
    ASSERT(pThread != NULL);
    if (pThread == NULL)
        return STATUS_INVALID_PARAMETER;

    // Allocate APC
    PKAPC pPrepareApc = NULL;
    PKAPC pInjectApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), BB_POOL_TAG);

    if (pInjectApc == NULL)
    {
        DPRINT("BlackBone: %s: Failed to allocate APC\n", __FUNCTION__);
        return STATUS_NO_MEMORY;
    }

    // Actual APC
    KeInitializeApc(
        pInjectApc, (PKTHREAD)pThread,
        OriginalApcEnvironment, &KernelApcInjectCallback,
        NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)pUserFunc, UserMode, Arg1
    );

    // Setup force-delivery APC
    if (bForce)
    {
        pPrepareApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), BB_POOL_TAG);
        KeInitializeApc(
            pPrepareApc, (PKTHREAD)pThread,
            OriginalApcEnvironment, &KernelApcPrepareCallback,
            NULL, NULL, KernelMode, NULL
        );
    }

    // Insert APC
    if (KeInsertQueueApc(pInjectApc, Arg2, Arg3, 0))
    {
        if (bForce && pPrepareApc)
            KeInsertQueueApc(pPrepareApc, NULL, NULL, 0);

        return STATUS_SUCCESS;
    }
    else
    {
        DPRINT("BlackBone: %s: Failed to insert APC\n", __FUNCTION__);

        ExFreePoolWithTag(pInjectApc, BB_POOL_TAG);

        if (pPrepareApc)
            ExFreePoolWithTag(pPrepareApc, BB_POOL_TAG);

        return STATUS_NOT_CAPABLE;
    }
}

/// <summary>
/// Inject dll using APC
/// Must be running in target process context
/// </summary>
/// <param name="pUserBuf">Injcetion code</param>
/// <param name="pProcess">Target process</param>
/// <param name="initRVA">Init routine RVA</param>
/// <param name="InitArg">Init routine argument</param>
/// <returns>Status code</returns>
NTSTATUS BBApcInject(IN PINJECT_BUFFER pUserBuf, IN PEPROCESS pProcess, IN ULONG initRVA, IN PCWCHAR InitArg)
{
    NTSTATUS status = STATUS_SUCCESS;
    PETHREAD pThread = NULL;

    // Get suitable thread
    status = BBLookupProcessThread(pProcess, &pThread);

    if (NT_SUCCESS(status))
    {
        status = BBQueueUserApc(pThread, pUserBuf->code, NULL, NULL, NULL, TRUE);

        // Wait for completion
        if (NT_SUCCESS(status))
        {
            LARGE_INTEGER interval = { 0 };
            interval.QuadPart = -(5LL * 10 * 1000);

            for (ULONG i = 0; i < 10000; i++)
            {
                if (BBCheckProcessTermination(PsGetCurrentProcess()) || PsIsThreadTerminating(pThread))
                {
                    status = STATUS_PROCESS_IS_TERMINATING;
                    break;
                }

                if (pUserBuf->complete == CALL_COMPLETE)
                    break;

                if (!NT_SUCCESS(status = KeDelayExecutionThread(KernelMode, FALSE, &interval)))
                    break;
            }

            // Check LdrLoadDll status
            if (NT_SUCCESS(status))
            {
                status = pUserBuf->status;
            }
            else
                DPRINT("BlackBone: %s: APC injection abnormal termination, status 0x%X\n", __FUNCTION__, status);

            // Call init routine
            if (NT_SUCCESS(status))
            {
                if (pUserBuf->module != 0)
                {
                    if (initRVA != 0)
                    {
                        RtlCopyMemory((PUCHAR)pUserBuf->buffer, InitArg, sizeof(pUserBuf->buffer));
                        BBQueueUserApc(pThread, (PUCHAR)pUserBuf->module + initRVA, pUserBuf->buffer, NULL, NULL, TRUE);

                        // Wait some time for routine to finish
                        interval.QuadPart = -(100LL * 10 * 1000);
                        KeDelayExecutionThread(KernelMode, FALSE, &interval);
                    }
                }
                else
                    DPRINT("BlackBone: %s: APC injection failed with unknown status\n", __FUNCTION__);
            }
            else
                DPRINT("BlackBone: %s: APC injection failed with status 0x%X\n", __FUNCTION__, status);
        }
    }
    else
        DPRINT("BlackBone: %s: Failed to locate thread\n", __FUNCTION__);

    if (pThread)
        ObDereferenceObject(pThread);

    return status;
}

/// <summary>
/// Build injection code for native x64 process
/// Must be running in target process context
/// </summary>
/// <param name="LdrLoadDll">LdrLoadDll address</param>
/// <param name="pPath">Path to the dll</param>
/// <returns>Code pointer. When not needed it should be freed with ZwFreeVirtualMemory</returns>
PINJECT_BUFFER BBGetNativeCode(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    PINJECT_BUFFER pBuffer = NULL;
    SIZE_T size = PAGE_SIZE;

    // Code
    UCHAR code[] =
    {
        0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
        0x48, 0x31, 0xC9,                       // xor rcx, rcx
        0x48, 0x31, 0xD2,                       // xor rdx, rdx
        0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
        0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
        0xFF, 0xD0,                             // call rax
        0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
        0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
        0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +60
        0x89, 0x02,                             // mov [rdx], eax
        0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
        0xC3                                    // ret
    };

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(status))
    {
        // Copy path
        PUNICODE_STRING pUserPath = &pBuffer->path;
        pUserPath->Length = 0;
        pUserPath->MaximumLength = sizeof(pBuffer->buffer);
        pUserPath->Buffer = pBuffer->buffer;

        RtlUnicodeStringCopy(pUserPath, pPath);

        // Copy code
        memcpy(pBuffer, code, sizeof(code));

        // Fill stubs
        *(ULONGLONG*)((PUCHAR)pBuffer + 12) = (ULONGLONG)pUserPath;
        *(ULONGLONG*)((PUCHAR)pBuffer + 22) = (ULONGLONG)&pBuffer->module;
        *(ULONGLONG*)((PUCHAR)pBuffer + 32) = (ULONGLONG)LdrLoadDll;
        *(ULONGLONG*)((PUCHAR)pBuffer + 44) = (ULONGLONG)&pBuffer->complete;
        *(ULONGLONG*)((PUCHAR)pBuffer + 60) = (ULONGLONG)&pBuffer->status;

        return pBuffer;
    }

    UNREFERENCED_PARAMETER(pPath);
    return NULL;
}

/// <summary>
/// Get module base address by name
/// </summary>
/// <param name="pProcess">Target process</param>
/// <param name="ModuleName">Nodule name to search for</param>
/// <param name="isWow64">If TRUE - search in 32-bit PEB</param>
/// <returns>Found address, NULL if not found</returns>
PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
{
    UNREFERENCED_PARAMETER(isWow64);
    ASSERT(pProcess != NULL);
    if (pProcess == NULL)
        return NULL;

    // Protect from UserMode AV
    __try
    {
        LARGE_INTEGER time = { 0 };
        time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

        // :不使用
        // Wow64 process
        /*
        if (isWow64)
        {
            PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
            if (pPeb32 == NULL)
            {
                DPRINT("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Wait for loader a bit
            for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
            {
                DPRINT("BlackBone: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
                KeDelayExecutionThread(KernelMode, TRUE, &time);
            }

            // Still no loader
            if (!pPeb32->Ldr)
            {
                DPRINT("BlackBone: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Search in InLoadOrderModuleList
            for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
                pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
                pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
            {
                UNICODE_STRING ustr;
                PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

                RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

                if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
                    return (PVOID)pEntry->DllBase;
            }
        }
        
        */
        // Native process
        //else
        {
            PPEB pPeb = PsGetProcessPeb(pProcess);
            
            if (!pPeb)
            {
                DPRINT("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Wait for loader a bit
            for (INT i = 0; !pPeb->Ldr && i < 10; i++)
            {
                DPRINT("BlackBone: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
                KeDelayExecutionThread(KernelMode, TRUE, &time);
            }

            // Still no loader
            if (!pPeb->Ldr)
            {
                DPRINT("BlackBone: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
                return NULL;
            }

            // Search in InLoadOrderModuleList
            for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
                pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
                pListEntry = pListEntry->Flink)
            {
                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
                    return pEntry->DllBase;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("BlackBone: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
    }

    return NULL;
}

/// <summary>
/// Get exported function address
/// </summary>
/// <param name="pBase">Module base</param>
/// <param name="name_ord">Function name or ordinal</param>
/// <param name="pProcess">Target process for user module</param>
/// <param name="baseName">Dll name for api schema</param>
/// <returns>Found address, NULL if not found</returns>
PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName)
{
    UNREFERENCED_PARAMETER(baseName);
    UNREFERENCED_PARAMETER(pProcess);

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
    PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
    PIMAGE_EXPORT_DIRECTORY pExport = NULL;
    ULONG expSize = 0;
    ULONG_PTR pAddress = 0;

    ASSERT(pBase != NULL);
    if (pBase == NULL)
        return NULL;

    /// Not a PE file
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

    // Not a PE file
    if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // 64 bit image
    if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    // 32 bit image
    else
    {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
    PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
    PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

    for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
    {
        USHORT OrdIndex = 0xFFFF;
        PCHAR  pName = NULL;

        // Find by index
        if ((ULONG_PTR)name_ord <= 0xFFFF)
        {
            OrdIndex = (USHORT)i;
        }
        // Find by name
        else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
        {
            pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
            OrdIndex = pAddressOfOrds[i];
        }
        // Weird params
        else
            return NULL;

        if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
            ((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
        {
            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

            // :不适用，因为我们只获取LdrLoadDll
            // Check forwarded export
            /*
            if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
            {
                WCHAR strbuf[256] = { 0 };
                ANSI_STRING forwarder = { 0 };
                ANSI_STRING import = { 0 };

                UNICODE_STRING uForwarder = { 0 };
                ULONG delimIdx = 0;
                PVOID forwardBase = NULL;
                PVOID result = NULL;

                // System image, not supported
                if (pProcess == NULL)
                    return NULL;

                RtlInitAnsiString(&forwarder, (PCSZ)pAddress);
                RtlInitEmptyUnicodeString(&uForwarder, strbuf, sizeof(strbuf));

                RtlAnsiStringToUnicodeString(&uForwarder, &forwarder, FALSE);
                for (ULONG j = 0; j < uForwarder.Length / sizeof(WCHAR); j++)
                {
                    if (uForwarder.Buffer[j] == L'.')
                    {
                        uForwarder.Length = (USHORT)(j * sizeof(WCHAR));
                        uForwarder.Buffer[j] = L'\0';
                        delimIdx = j;
                        break;
                    }
                }

                // Get forward function name/ordinal
                RtlInitAnsiString(&import, forwarder.Buffer + delimIdx + 1);
                RtlAppendUnicodeToString(&uForwarder, L".dll");

                //
                // Check forwarded module
                //
                UNICODE_STRING resolved = { 0 };
                UNICODE_STRING resolvedName = { 0 };
                BBResolveImagePath(NULL, pProcess, KApiShemaOnly, &uForwarder, baseName, &resolved);
                BBStripPath(&resolved, &resolvedName);

                forwardBase = BBGetUserModule(pProcess, &resolvedName, PsGetProcessWow64Process(pProcess) != NULL);
                result = BBGetModuleExport(forwardBase, import.Buffer, pProcess, &resolvedName);
                RtlFreeUnicodeString(&resolved);

                return result;
            }
            */
            break;
        }
    }

    return (PVOID)pAddress;
}
