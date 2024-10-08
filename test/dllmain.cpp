// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"


DWORD WINAPI Start(
    LPVOID lpThreadParameter
    )
{
    CreateFile(L"C:\\Users\\test\\Desktop\\winlogon.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,0);

    do {
        Sleep(10 * 1000);
    } while (TRUE);

    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, Start, 0, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

