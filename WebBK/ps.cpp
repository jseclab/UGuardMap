#pragma once
#include "bb.h"
#include "ps.h"

SIZE_T GetProcessIdByName(CONST LPWSTR name)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG bufferSize = 0;
	
	if (ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize) == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (bufferSize)
		{
			PVOID memory = ExAllocatePoolWithTag(PagedPool, bufferSize, PS_POOL_TAG);

			if (memory)
			{
				ntstatus = ZwQuerySystemInformation(SystemProcessInformation, memory, bufferSize, &bufferSize);

				if (NT_SUCCESS(ntstatus))
				{
					PSYSTEM_PROCESSES processEntry = (PSYSTEM_PROCESSES)memory;

					do {
						if (processEntry->ProcessName.Length) 
						{
							UNICODE_STRING nameUnicode;
							RtlInitUnicodeString(&nameUnicode, name);

							if (!RtlCompareUnicodeString(&processEntry->ProcessName, &nameUnicode, TRUE))
								return processEntry->ProcessId;
						}
						processEntry = (PSYSTEM_PROCESSES)((UCHAR*)processEntry + processEntry->NextEntryDelta);
					} while (processEntry->NextEntryDelta);
				}
			}
		}
	}

	return 0;
}