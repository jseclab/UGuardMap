
#include "bb.h"
#include "ps.h"

#define JMP_SIZE (14)
#define MAPPER_DATA_SIZE (JMP_SIZE + 7)

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS MainThread();

__declspec(dllexport) volatile UCHAR mapperData[MAPPER_DATA_SIZE];

BOOLEAN MemCopyWP(PVOID dest, PVOID src, ULONG length) {
    PMDL mdl = IoAllocateMdl(dest, length, FALSE, FALSE, NULL);
    if (!mdl) {
        return FALSE;
    }

    MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, 0, HighPagePriority);
    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    memcpy(mapped, src, length);

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return TRUE;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath,_In_ DRIVER_INITIALIZE HookFunc)
{
    MemCopyWP(HookFunc, (PVOID)mapperData, sizeof(mapperData));
    MainThread();
    return HookFunc(DriverObject, RegistryPath);
}

void ThreadFunction(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL * 10; // 10s

    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    // 执行创建文件的函数
    delay.QuadPart = -10000000LL * 3; // 3s
    SIZE_T targetId = 0;

    do {
        targetId = GetProcessIdByName(L"winlogon.exe");

        if (targetId > 0)
            break;
        
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

    } while (TRUE);

    INJECT_DLL data;
    RtlSecureZeroMemory(&data, sizeof(data));

    data.pid = targetId;
    wchar_t* ori_path = L"C:\\Users\\test\\Desktop\\vkkkk1.dll";
    RtlCopyMemory(data.FullDllPath, ori_path, wcslen(ori_path) * sizeof(wchar_t));
    data.type = IT_Apc;
    data.unlink = FALSE;
    data.erasePE = FALSE;
    data.initRVA = 0;
    BBInjectDll(&data);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS MainThread()
{
    HANDLE threadHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    NTSTATUS status;

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(&threadHandle,
        THREAD_ALL_ACCESS,
        &objectAttributes,
        NULL,
        &clientId,
        ThreadFunction,
        NULL);

    if (NT_SUCCESS(status))
        ZwClose(threadHandle);

    return status;
}
