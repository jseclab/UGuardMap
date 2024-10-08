#include "EfiGuardDxe.h"

#include <Library/BaseMemoryLib.h>


// Global kernel patch status information.
//
// The justification for statically allocating these ~8KB is that this buffer will be accessible during both contexts of winload.efi. Winload has two
// runtime contexts: the real mode firmware context (= 1), in which EFI services are accessible, and the protected mode application context (= 0),
// which has its own GDT, IDT and paging levels and which is used to set up the NT environment and enable virtual addressing. Winload switches between
// the two with BlpArchSwitchContext() when needed. Because we cannot allocate memory in protected mode (e.g. in PatchNtoskrnl), and any memory
// allocated in real mode (e.g. in PatchWinload) will need address translation on later access, this is by far the simplest solution
// because it allows the buffer to be accessed from both contexts at all stages of driver execution.
KERNEL_PATCH_INFORMATION gKernelPatchInfo;


// Signature for nt!KeInitAmd64SpecificState
// This function is present in all x64 kernels since Vista. It generates a #DE due to 32 bit idiv quotient overflow.
STATIC CONST UINT8 SigKeInitAmd64SpecificState[] = {
	0xF7, 0xD9,					// neg ecx
	0x45, 0x1B, 0xC0,			// sbb r8d, r8d
	0x41, 0x83, 0xE0, 0xEE,		// and r8d, 0FFFFFFEEh
	0x41, 0x83, 0xC0, 0x11,		// add r8d, 11h
	0xD1, 0xCA,					// ror edx, 1
	0x8B, 0xC2,					// mov eax, edx
	0x99,						// cdq
	0x41, 0xF7, 0xF8			// idiv r8d
};

// Signature for nt!KiVerifyScopesExecute
// This function is present since Windows 8.1 and is responsible for executing all functions in the KiVerifyXcptRoutines array.
// One of these functions, KiVerifyXcpt15, will indirectly initialize a PatchGuard context from its exception handler.
STATIC CONST UINT8 SigKiVerifyScopesExecute[] = {
	0x83, 0xCC, 0xCC, 0x00,										// and d/qword ptr [REG+XX], 0
	0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE	// mov rax, 0FEFFFFFFFFFFFFFFh
};

// Signature for nt!KiMcaDeferredRecoveryService
// This function is present since Windows 8.1 and bugchecks the system with bugcode 0x109 after zeroing registers.
// It is called by KiScanQueues and KiSchedulerDpc, two PatchGuard DPCs which may be queued from various unrelated kernel functions.
STATIC CONST UINT8 SigKiMcaDeferredRecoveryService[] = {
	0x33, 0xC0,												// xor eax, eax
	0x8B, 0xD8,												// mov ebx, eax
	0x8B, 0xF8,												// mov edi, eax
	0x8B, 0xE8,												// mov ebp, eax
	0x4C, 0x8B, 0xD0										// mov r10, rax
};

// Signature for nt!KiSwInterrupt
// This function is present since Windows 10 and is the interrupt handler for int 20h.
// This interrupt is a spurious interrupt on older versions of Windows, and does nothing useful on Windows 10.
// If int 20h is issued from kernel mode, the PatchGuard verification routine KiSwInterruptDispatch is called.
STATIC CONST UINT8 SigKiSwInterrupt[] = {
	0xFB,													// sti
	0x48, 0x8D, 0xCC, 0xCC,									// lea REG, [REG-XX]
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,							// call KiSwInterruptDispatch
	0xFA													// cli
};
STATIC CONST UINTN SigKiSwInterruptCallOffset = 5, SigKiSwInterruptCliOffset = 10;

// Signature for nt!SeCodeIntegrityQueryInformation, called through NtQuerySystemInformation(SystemCodeIntegrityInformation).
// This function has actually existed since Vista in various forms, sometimes (8/8.1/early 10) inlined in ExpQuerySystemInformation.
// This signature is only for the Windows 10 RS3+ version. I could add more signatures but this is a pretty superficial patch anyway.
STATIC CONST UINT8 SigSeCodeIntegrityQueryInformation[] = {
	0x48, 0x83, 0xEC,										// sub rsp, XX
	0xCC, 0x48, 0x83, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC, 0x00,	// cmp ds:qword_xxxx, 0
	0x4D, 0x8B, 0xC8,										// mov r9, r8
	0x4C, 0x8B, 0xD1,										// mov r10, rcx
	0x74, 0xCC												// jz XX
};

// Patched SeCodeIntegrityQueryInformation which reports that DSE is enabled
STATIC CONST UINT8 SeCodeIntegrityQueryInformationPatch[] = {
	0x41, 0xC7, 0x00, 0x08, 0x00, 0x00, 0x00,				// mov dword ptr [r8], 8
	0x33, 0xC0,												// xor eax, eax
	0xC7, 0x41, 0x04, 0x01, 0x00, 0x00, 0x00,				// mov dword ptr [rcx+4], 1
	0xC3													// ret
};


//
// Defuses PatchGuard initialization routines before execution is transferred to the kernel.
// All code accessed here is located in the INIT and .text sections.
//
STATIC
EFI_STATUS
EFIAPI
DisablePatchGuard(
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN PEFI_IMAGE_SECTION_HEADER InitSection,
	IN PEFI_IMAGE_SECTION_HEADER TextSection,
	IN UINT16 BuildNumber
	)
{
	UINT32 StartRva = InitSection->VirtualAddress;
	UINT32 SizeOfRawData = InitSection->SizeOfRawData;
	UINT8* StartVa = ImageBase + StartRva;

	// Search for KeInitAmd64SpecificState
	PRINT_KERNEL_PATCH_MSG(L"\r\n== Searching for nt!KeInitAmd64SpecificState pattern in INIT ==\r\n");
	UINT8* KeInitAmd64SpecificStatePatternAddress = NULL;
	for (UINT8* Address = StartVa; Address < StartVa + SizeOfRawData - sizeof(SigKeInitAmd64SpecificState); ++Address)
	{
		if (CompareMem(Address, SigKeInitAmd64SpecificState, sizeof(SigKeInitAmd64SpecificState)) == 0)
		{
			KeInitAmd64SpecificStatePatternAddress = Address;
			PRINT_KERNEL_PATCH_MSG(L"    Found KeInitAmd64SpecificState pattern at 0x%llX.\r\n", (UINTN)KeInitAmd64SpecificStatePatternAddress);
			break;
		}
	}

	// Backtrack to function start
	UINT8* KeInitAmd64SpecificState = BacktrackToFunctionStart(ImageBase, NtHeaders, KeInitAmd64SpecificStatePatternAddress);
	if (KeInitAmd64SpecificState == NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Failed to find KeInitAmd64SpecificState%S.\r\n",
			(KeInitAmd64SpecificStatePatternAddress == NULL ? L" pattern" : L""));
		return EFI_NOT_FOUND;
	}

	// Search for CcInitializeBcbProfiler (Win 8+) / <HUGEFUNC> (Win Vista/7)
	// Most variables below use the 'CcInitializeBcbProfiler' name, which is not really accurate for Windows Vista/7 but close enough.
	// For debug prints, call the function "<HUGEFUNC>" instead if we're on Windows Vista/7. (seriously, it's fucking huge)
	CONST CHAR16* FuncName = BuildNumber >= 9200 ? L"CcInitializeBcbProfiler" : L"<HUGEFUNC>";
	PRINT_KERNEL_PATCH_MSG(L"== Disassembling INIT to find nt!%S ==\r\n", FuncName);
	UINT8* CcInitializeBcbProfilerPatternAddress = NULL;

	// On Windows Vista/7 we need to find the address of RtlPcToFileHeader, which will help identify HUGEFUNC as no other function calls this
	UINTN RtlPcToFileHeader = 0;
	if (BuildNumber < 9200)
	{
		RtlPcToFileHeader = (UINTN)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "RtlPcToFileHeader");
		if (RtlPcToFileHeader == 0)
		{
			PRINT_KERNEL_PATCH_MSG(L"Failed to find RtlPcToFileHeader export.\r\n");
			return EFI_NOT_FOUND;
		}
	}

	// Initialize Zydis
	ZYDIS_CONTEXT Context;
	ZyanStatus Status = ZydisInit(NtHeaders, &Context);
	if (!ZYAN_SUCCESS(Status))
	{
		PRINT_KERNEL_PATCH_MSG(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	Context.Length = SizeOfRawData;
	Context.Offset = 0;

	// Start decode loop
	while ((Context.InstructionAddress = (ZyanU64)(StartVa + Context.Offset),
			Status = ZydisDecoderDecodeFull(&Context.Decoder,
											(VOID*)Context.InstructionAddress,
											Context.Length - Context.Offset,
											&Context.Instruction,
											Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
	{
		if (!ZYAN_SUCCESS(Status))
		{
			Context.Offset++;
			continue;
		}

		if (BuildNumber < 9200)
		{
			// Windows Vista/7: check if this is 'call IMM'
			if (Context.Instruction.operand_count == 4 &&
				Context.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && Context.Operands[0].imm.is_relative == ZYAN_TRUE &&
				Context.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
			{
				// Check if this is 'call RtlPcToFileHeader'
				ZyanU64 OperandAddress = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &OperandAddress)) &&
					OperandAddress == RtlPcToFileHeader)
				{
					CcInitializeBcbProfilerPatternAddress = (UINT8*)Context.InstructionAddress;
					PRINT_KERNEL_PATCH_MSG(L"    Found 'call RtlPcToFileHeader' at 0x%llX.\r\n", (UINTN)CcInitializeBcbProfilerPatternAddress);
					break;
				}
			}
		}
		else
		{
			// Windows 8+: check if this is 'mov [al|rax], 0x0FFFFF780000002D4' ; SharedUserData->KdDebuggerEnabled
			if ((Context.Instruction.operand_count == 2 && Context.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV && Context.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) &&
				((Context.Operands[0].reg.value == ZYDIS_REGISTER_AL && Context.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
					(UINT64)(Context.Operands[1].mem.disp.value) == 0x0FFFFF780000002D4ULL) ||
				(Context.Operands[0].reg.value == ZYDIS_REGISTER_RAX && Context.Operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					Context.Operands[1].imm.value.u == 0x0FFFFF780000002D4ULL)))
			{
				CcInitializeBcbProfilerPatternAddress = (UINT8*)Context.InstructionAddress;
				PRINT_KERNEL_PATCH_MSG(L"    Found CcInitializeBcbProfiler pattern at 0x%llX.\r\n", (UINTN)CcInitializeBcbProfilerPatternAddress);
				break;
			}
		}

		Context.Offset += Context.Instruction.length;
	}

	// Backtrack to function start
	UINT8* CcInitializeBcbProfiler = BacktrackToFunctionStart(ImageBase, NtHeaders, CcInitializeBcbProfilerPatternAddress);
	if (CcInitializeBcbProfiler == NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Failed to find %S%S.\r\n",
			FuncName, (CcInitializeBcbProfilerPatternAddress == NULL ? L" pattern" : L""));
		return EFI_NOT_FOUND;
	}

	// Search for ExpLicenseWatchInitWorker (only exists on Windows >= 8)
	UINT8* ExpLicenseWatchInitWorker = NULL;
	if (BuildNumber >= 9200)
	{
		PRINT_KERNEL_PATCH_MSG(L"== Disassembling INIT to find nt!ExpLicenseWatchInitWorker ==\r\n");
		UINT8* ExpLicenseWatchInitWorkerPatternAddress = NULL;

		// Start decode loop
		Context.Offset = 0;
		while ((Context.InstructionAddress = (ZyanU64)(StartVa + Context.Offset),
				Status = ZydisDecoderDecodeFull(&Context.Decoder,
												(VOID*)Context.InstructionAddress,
												Context.Length - Context.Offset,
												&Context.Instruction,
												Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
		{
			if (!ZYAN_SUCCESS(Status))
			{
				Context.Offset++;
				continue;
			}

			// Check if this is 'mov al, ds:[0x0FFFFF780000002D4]' ; SharedUserData->KdDebuggerEnabled
			// The address must also obviously not be the CcInitializeBcbProfiler one we just found
			if ((UINT8*)Context.InstructionAddress != CcInitializeBcbProfilerPatternAddress &&
				Context.Instruction.operand_count == 2 && Context.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
				Context.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Context.Operands[0].reg.value == ZYDIS_REGISTER_AL &&
				Context.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && Context.Operands[1].mem.segment == ZYDIS_REGISTER_DS &&
				Context.Operands[1].mem.disp.value == 0x0FFFFF780000002D4LL)
			{
				ExpLicenseWatchInitWorkerPatternAddress = (UINT8*)Context.InstructionAddress;
				PRINT_KERNEL_PATCH_MSG(L"    Found ExpLicenseWatchInitWorker pattern at 0x%llX.\r\n", (UINTN)ExpLicenseWatchInitWorkerPatternAddress);
				break;
			}

			Context.Offset += Context.Instruction.length;
		}

		// Backtrack to function start
		ExpLicenseWatchInitWorker = BacktrackToFunctionStart(ImageBase, NtHeaders, ExpLicenseWatchInitWorkerPatternAddress);
		if (ExpLicenseWatchInitWorker == NULL)
		{
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find ExpLicenseWatchInitWorker%S.\r\n",
				(ExpLicenseWatchInitWorkerPatternAddress == NULL ? L" pattern" : L""));
			return EFI_NOT_FOUND;
		}
	}

	// Search for KiVerifyScopesExecute (only exists on Windows >= 8.1)
	UINT8* KiVerifyScopesExecute = NULL;
	if (BuildNumber >= 9600)
	{
		PRINT_KERNEL_PATCH_MSG(L"== Searching for nt!KiVerifyScopesExecute pattern in INIT ==\r\n");
		UINT8* KiVerifyScopesExecutePatternAddress = NULL;
		CONST EFI_STATUS FindKiVerifyScopesExecuteStatus = FindPattern(SigKiVerifyScopesExecute,
																	0xCC,
																	sizeof(SigKiVerifyScopesExecute),
																	StartVa,
																	SizeOfRawData,
																	(VOID**)&KiVerifyScopesExecutePatternAddress);
		if (EFI_ERROR(FindKiVerifyScopesExecuteStatus))
		{
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find KiVerifyScopesExecute pattern.\r\n");
			return EFI_NOT_FOUND;
		}
		PRINT_KERNEL_PATCH_MSG(L"    Found KiVerifyScopesExecute pattern at 0x%llX.\r\n", (UINTN)KiVerifyScopesExecutePatternAddress);

		// Backtrack to function start
		KiVerifyScopesExecute = BacktrackToFunctionStart(ImageBase, NtHeaders, KiVerifyScopesExecutePatternAddress);
		if (KiVerifyScopesExecute == NULL)
		{
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find KiVerifyScopesExecute.\r\n");
			return EFI_NOT_FOUND;
		}
	}

	// Search for callers of KiMcaDeferredRecoveryService (only exists on Windows >= 8.1)
	UINT8* KiMcaDeferredRecoveryServiceCallers[2];
	ZeroMem(KiMcaDeferredRecoveryServiceCallers, sizeof(KiMcaDeferredRecoveryServiceCallers));
	if (BuildNumber >= 9600)
	{
		StartRva = TextSection->VirtualAddress;
		SizeOfRawData = TextSection->SizeOfRawData;
		StartVa = ImageBase + StartRva;

		// Search for KiMcaDeferredRecoveryService
		PRINT_KERNEL_PATCH_MSG(L"== Searching for nt!KiMcaDeferredRecoveryService pattern in .text ==\r\n");
		UINT8* KiMcaDeferredRecoveryService = NULL;
		for (UINT8* Address = StartVa; Address < StartVa + SizeOfRawData - sizeof(SigKiMcaDeferredRecoveryService); ++Address)
		{
			if (CompareMem(Address, SigKiMcaDeferredRecoveryService, sizeof(SigKiMcaDeferredRecoveryService)) == 0)
			{
				KiMcaDeferredRecoveryService = Address;
				PRINT_KERNEL_PATCH_MSG(L"    Found KiMcaDeferredRecoveryService pattern at 0x%llX.\r\n", (UINTN)KiMcaDeferredRecoveryService);
				break;
			}
		}

		if (KiMcaDeferredRecoveryService == NULL)
		{
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find KiMcaDeferredRecoveryService.\r\n");
			return EFI_NOT_FOUND;
		}

		// Start decode loop
		Context.Length = SizeOfRawData;
		Context.Offset = 0;
		while ((Context.InstructionAddress = (ZyanU64)(StartVa + Context.Offset),
				Status = ZydisDecoderDecodeFull(&Context.Decoder,
												(VOID*)Context.InstructionAddress,
												Context.Length - Context.Offset,
												&Context.Instruction,
												Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
		{
			if (!ZYAN_SUCCESS(Status))
			{
				Context.Offset++;
				continue;
			}

			// Check if this is 'call KiMcaDeferredRecoveryService'
			ZyanU64 OperandAddress = 0;	
			if (Context.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
				ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)KiMcaDeferredRecoveryService)
			{
				if (KiMcaDeferredRecoveryServiceCallers[0] == NULL)
				{
					KiMcaDeferredRecoveryServiceCallers[0] = (UINT8*)Context.InstructionAddress;
				}
				else if (KiMcaDeferredRecoveryServiceCallers[1] == NULL)
				{
					KiMcaDeferredRecoveryServiceCallers[1] = (UINT8*)Context.InstructionAddress;
					break;
				}
			}

			Context.Offset += Context.Instruction.length;
		}

		// Backtrack to function start
		KiMcaDeferredRecoveryServiceCallers[0] = BacktrackToFunctionStart(ImageBase, NtHeaders, KiMcaDeferredRecoveryServiceCallers[0]);
		KiMcaDeferredRecoveryServiceCallers[1] = BacktrackToFunctionStart(ImageBase, NtHeaders, KiMcaDeferredRecoveryServiceCallers[1]);
		if (KiMcaDeferredRecoveryServiceCallers[0] == NULL || KiMcaDeferredRecoveryServiceCallers[1] == NULL)
		{
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find KiMcaDeferredRecoveryService callers.\r\n");
			return EFI_NOT_FOUND;
		}
	}

	// We need KiSwInterruptDispatch to call ExAllocatePool2 for our preferred method to work, because we rely on it to
	// return null for zero pool tags. Windows 10 20H1 does export ExAllocatePool2, but without using it where we need it.
	CONST BOOLEAN FindGlobalPgContext = BuildNumber >= 20348 && GetProcedureAddress((UINTN)ImageBase, NtHeaders, "ExAllocatePool2") != NULL;

	// Search for KiSwInterrupt[Dispatch] and optionally its global PatchGuard context (named g_PgContext here). Both of these only exist on Windows >= 10
	UINT8* KiSwInterruptPatternAddress = NULL, *gPgContext = NULL;
	if (BuildNumber >= 10240)
	{
		StartRva = TextSection->VirtualAddress;
		SizeOfRawData = TextSection->SizeOfRawData;
		StartVa = ImageBase + StartRva;

		PRINT_KERNEL_PATCH_MSG(L"== Searching for nt!KiSwInterrupt pattern in .text ==\r\n");
		UINT8* KiSwInterruptDispatchAddress = NULL;
		CONST EFI_STATUS FindKiSwInterruptStatus = FindPattern(SigKiSwInterrupt,
																0xCC,
																sizeof(SigKiSwInterrupt),
																StartVa,
																SizeOfRawData,
																(VOID**)&KiSwInterruptPatternAddress);
		if (EFI_ERROR(FindKiSwInterruptStatus))
		{
			// This is not a fatal error as the system can still boot without patching g_PgContext or KiSwInterrupt.
			// However note that in this case, any attempt to issue int 20h from kernel mode later will result in a bugcheck.
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find KiSwInterrupt. Skipping patch.\r\n");
		}
		else
		{
			ASSERT(SigKiSwInterrupt[SigKiSwInterruptCallOffset] == 0xE8 && SigKiSwInterrupt[SigKiSwInterruptCliOffset] == 0xFA);
			CONST INT32 Relative = *(INT32*)(KiSwInterruptPatternAddress + SigKiSwInterruptCallOffset + 1);
			KiSwInterruptDispatchAddress = KiSwInterruptPatternAddress + SigKiSwInterruptCliOffset + Relative;
			
			PRINT_KERNEL_PATCH_MSG(L"    Found KiSwInterrupt pattern at 0x%llX.\r\n", (UINTN)KiSwInterruptPatternAddress);
		}

		if (KiSwInterruptDispatchAddress != NULL && FindGlobalPgContext)
		{
			// Start decode loop
			Context.Length = 128;
			Context.Offset = 0;
			while ((Context.InstructionAddress = (ZyanU64)(KiSwInterruptDispatchAddress + Context.Offset),
					Status = ZydisDecoderDecodeFull(&Context.Decoder,
													(VOID*)Context.InstructionAddress,
													Context.Length - Context.Offset,
													&Context.Instruction,
													Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
			{
				if (!ZYAN_SUCCESS(Status))
				{
					Context.Offset++;
					continue;
				}

				// Check if this is 'mov REG, ds:g_PgContext'
				if (Context.Instruction.operand_count == 2 &&
					Context.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
					(Context.Instruction.attributes & ZYDIS_ATTRIB_ACCEPTS_SEGMENT) != 0 &&
					Context.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					Context.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && Context.Operands[1].mem.base == ZYDIS_REGISTER_RIP &&
					(Context.Operands[1].mem.segment == ZYDIS_REGISTER_CS || Context.Operands[1].mem.segment == ZYDIS_REGISTER_DS))
				{
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[1], Context.InstructionAddress, (ZyanU64*)&gPgContext)))
					{
						PRINT_KERNEL_PATCH_MSG(L"    Found g_PgContext at 0x%llX.\r\n", (UINTN)gPgContext);
						break;
					}
				}

				Context.Offset += Context.Instruction.length;
			}
		}
	}

	// We have all the addresses we need; now do the actual patching.
	CONST UINT32 Yes = 0xC301B0;	// mov al, 1, ret
	CONST UINT32 No = 0xC3C033;		// xor eax, eax, ret
	CopyWpMem(KeInitAmd64SpecificState, &No, sizeof(No));
	CopyWpMem(CcInitializeBcbProfiler, &Yes, sizeof(Yes));
	if (ExpLicenseWatchInitWorker != NULL)
		CopyWpMem(ExpLicenseWatchInitWorker, &No, sizeof(No));
	if (KiVerifyScopesExecute != NULL)
		CopyWpMem(KiVerifyScopesExecute, &No, sizeof(No));
	if (KiMcaDeferredRecoveryServiceCallers[0] != NULL && KiMcaDeferredRecoveryServiceCallers[1] != NULL)
	{
		CopyWpMem(KiMcaDeferredRecoveryServiceCallers[0], &No, sizeof(No));
		CopyWpMem(KiMcaDeferredRecoveryServiceCallers[1], &No, sizeof(No));
	}
	if (gPgContext != NULL)
	{
		CONST UINT64 NewPgContextAddress = (UINT64)ImageBase + InitSection->VirtualAddress; // Address in discardable section
		CopyWpMem(gPgContext, &NewPgContextAddress, sizeof(NewPgContextAddress));
	}
	else if (KiSwInterruptPatternAddress != NULL)
	{
		SetWpMem(KiSwInterruptPatternAddress, sizeof(SigKiSwInterrupt), 0x90); // 11 x nop
	}

	// Print info
	PRINT_KERNEL_PATCH_MSG(L"\r\n    Patched KeInitAmd64SpecificState [RVA: 0x%X].\r\n",
		(UINT32)(KeInitAmd64SpecificState - ImageBase));
	PRINT_KERNEL_PATCH_MSG(L"    Patched %ls [RVA: 0x%X].\r\n",
		FuncName, (UINT32)(CcInitializeBcbProfiler - ImageBase));
	if (ExpLicenseWatchInitWorker != NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Patched ExpLicenseWatchInitWorker [RVA: 0x%X].\r\n",
			(UINT32)(ExpLicenseWatchInitWorker - ImageBase));
	}
	if (KiVerifyScopesExecute != NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Patched KiVerifyScopesExecute [RVA: 0x%X].\r\n",
			(UINT32)(KiVerifyScopesExecute - ImageBase));
	}
	if (KiMcaDeferredRecoveryServiceCallers[0] != NULL && KiMcaDeferredRecoveryServiceCallers[1] != NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Patched KiMcaDeferredRecoveryService [RVAs: 0x%X, 0x%X].\r\n",
			(UINT32)(KiMcaDeferredRecoveryServiceCallers[0] - ImageBase),
			(UINT32)(KiMcaDeferredRecoveryServiceCallers[1] - ImageBase));
	}
	if (gPgContext != NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Patched g_PgContext [RVA: 0x%X].\r\n",
			(UINT32)(gPgContext - ImageBase));
	}
	else if (KiSwInterruptPatternAddress != NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Patched KiSwInterrupt [RVA: 0x%X].\r\n",
			(UINT32)(KiSwInterruptPatternAddress - ImageBase));
	}

	return EFI_SUCCESS;
}

//
// Disables DSE for the duration of the boot by preventing it from initializing.
// This function is only called if DseBypassMethod is DSE_DISABLE_AT_BOOT, or if the Windows version is Vista or 7
// and DseBypassMethod is DSE_DISABLE_SETVARIABLE_HOOK. In the latter case, only one byte is patched to make
// the SetVariable backdoor safe to use more than once. DSE will still be fully initialized in this case.
// All code accessed here is located in the PAGE section.
//
STATIC
EFI_STATUS
EFIAPI
DisableDSE(
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN PEFI_IMAGE_SECTION_HEADER PageSection,
	IN EFIGUARD_DSE_BYPASS_TYPE BypassType,
	IN UINT16 BuildNumber
	)
{
	if (BypassType == DSE_DISABLE_NONE)
		return EFI_INVALID_PARAMETER;

	CONST UINT32 PageSizeOfRawData = PageSection->SizeOfRawData;
	CONST UINT8* PageStartVa = ImageBase + PageSection->VirtualAddress;

	// Find the ntoskrnl.exe IAT address for CI.dll!CiInitialize
	VOID* CiInitialize;
	CONST EFI_STATUS IatStatus = FindIATAddressForImport(ImageBase,
														NtHeaders,
														"CI.dll",
														"CiInitialize",
														&CiInitialize);
	if (EFI_ERROR(IatStatus))
	{
		PRINT_KERNEL_PATCH_MSG(L"Failed to find IAT address of CI.dll!CiInitialize.\r\n");
		return IatStatus;
	}

	PRINT_KERNEL_PATCH_MSG(L"\r\n== Disassembling PAGE to find nt!SepInitializeCodeIntegrity 'mov ecx, xxx' ==\r\n");

	// Initialize Zydis
	ZYDIS_CONTEXT Context;
	ZyanStatus Status = ZydisInit(NtHeaders, &Context);
	if (!ZYAN_SUCCESS(Status))
	{
		PRINT_KERNEL_PATCH_MSG(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	UINT8* SepInitializeCodeIntegrityMovEcxAddress = NULL;

	if (BuildNumber < 9200)
	{
		// On Windows Vista/7 we have an enormously annoying import thunk in .text to find. All it does is 'jmp __imp_CiInitialize'.
		// SepInitializeCodeIntegrity will then call this thunk. What a waste
		CONST PEFI_IMAGE_SECTION_HEADER TextSection = IMAGE_FIRST_SECTION(NtHeaders);
		VOID* JmpCiInitializeAddress = NULL;
		Context.Length = TextSection->SizeOfRawData;
		Context.Offset = 0;

		// Start decode loop
		while ((Context.InstructionAddress = (ZyanU64)(ImageBase + TextSection->VirtualAddress + Context.Offset),
				Status = ZydisDecoderDecodeFull(&Context.Decoder,
												(VOID*)Context.InstructionAddress,
												Context.Length - Context.Offset,
												&Context.Instruction,
												Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
		{
			if (!ZYAN_SUCCESS(Status))
			{
				Context.Offset++;
				continue;
			}

			if ((Context.Instruction.operand_count == 2 &&
				Context.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && Context.Operands[0].mem.base == ZYDIS_REGISTER_RIP) &&
				Context.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP)
			{
				// Check if this is 'jmp qword ptr ds:[CiInitialize IAT RVA]'
				ZyanU64 OperandAddress = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &OperandAddress)) &&
					OperandAddress == (UINTN)CiInitialize)
				{
					JmpCiInitializeAddress = (VOID*)Context.InstructionAddress;
					break;
				}
			}

			Context.Offset += Context.Instruction.length;
		}

		if (JmpCiInitializeAddress == NULL)
		{
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find 'jmp __imp_CiInitialize' import thunk.\r\n");
			return EFI_NOT_FOUND;
		}

		// Make this the new 'IAT address' to simplify checks below
		CiInitialize = JmpCiInitializeAddress;
	}

	UINT8* LastMovIntoEcx = NULL; // Keep track of 'mov ecx, xxx' - the last one before call/jmp cs:__imp_CiInitialize is the one we want to patch
	Context.Length = PageSizeOfRawData;
	Context.Offset = 0;

	// Start decode loop
	while ((Context.InstructionAddress = (ZyanU64)(PageStartVa + Context.Offset),
			Status = ZydisDecoderDecodeFull(&Context.Decoder,
											(VOID*)Context.InstructionAddress,
											Context.Length - Context.Offset,
											&Context.Instruction,
											Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
	{
		if (!ZYAN_SUCCESS(Status))
		{
			Context.Offset++;
			continue;
		}

		// Check if this is a 2-byte (size of our patch) 'mov ecx, <anything>' and store the instruction address if so
		if (Context.Instruction.operand_count == 2 && Context.Instruction.length == 2 && Context.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			Context.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Context.Operands[0].reg.value == ZYDIS_REGISTER_ECX)
		{
			LastMovIntoEcx = (UINT8*)Context.InstructionAddress;
		}
		else if ((BuildNumber >= 9200 &&
				((Context.Instruction.operand_count == 2 || Context.Instruction.operand_count == 4) &&
				(Context.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && Context.Operands[0].mem.base == ZYDIS_REGISTER_RIP) &&
				((Context.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP && Context.Instruction.operand_count == 2) ||
				(Context.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL && Context.Instruction.operand_count == 4))))
			||
			(BuildNumber < 9200 &&
				(Context.Instruction.operand_count == 4 &&
				Context.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && Context.Operands[0].imm.is_relative == ZYAN_TRUE &&
				Context.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL)))
		{
			// Check if this is
			// 'call IMM:CiInitialize thunk'				// E8 ?? ?? ?? ??			// Windows Vista/7
			// or
			// 'jmp qword ptr ds:[CiInitialize IAT RVA]'	// 48 FF 25 ?? ?? ?? ??		// Windows 8 through 10.0.15063.0
			// or
			// 'call qword ptr ds:[CiInitialize IAT RVA]'	// FF 15 ?? ?? ?? ??		// Windows 10.0.16299.0+
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)CiInitialize)
			{
				SepInitializeCodeIntegrityMovEcxAddress = LastMovIntoEcx; // The last 'mov ecx, xxx' before the call/jmp is the instruction we want
				PRINT_KERNEL_PATCH_MSG(L"    Found 'mov ecx, xxx' in SepInitializeCodeIntegrity [RVA: 0x%X].\r\n",
					(UINT32)(SepInitializeCodeIntegrityMovEcxAddress - ImageBase));
				break;
			}
		}

		Context.Offset += Context.Instruction.length;
	}

	if (SepInitializeCodeIntegrityMovEcxAddress == NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Failed to find SepInitializeCodeIntegrity 'mov ecx, xxx' pattern.\r\n");
		return EFI_NOT_FOUND;
	}

	ZyanU64 gCiEnabled = 0;
	if (BuildNumber < 9200)
	{
		// On Windows Vista/7, find g_CiEnabled now because it's a few bytes away and we'll it need later
		Context.Length = 32;
		Context.Offset = 0;

		while ((Context.InstructionAddress = (ZyanU64)(SepInitializeCodeIntegrityMovEcxAddress + Context.Offset),
				Status = ZydisDecoderDecodeFull(&Context.Decoder,
												(VOID*)Context.InstructionAddress,
												Context.Length - Context.Offset,
												&Context.Instruction,
												Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
		{
			if (!ZYAN_SUCCESS(Status))
			{
				Context.Offset++;
				continue;
			}

			// Check if this is 'mov g_CiEnabled, REG8'
			if (Context.Instruction.operand_count == 2 &&
				Context.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
				Context.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && Context.Operands[0].mem.base == ZYDIS_REGISTER_RIP &&
				Context.Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
			{
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &gCiEnabled)))
				{
					PRINT_KERNEL_PATCH_MSG(L"    Found g_CiEnabled at 0x%llX.\r\n", gCiEnabled);
					break;
				}
			}

			Context.Offset += Context.Instruction.length;
		}

		if (gCiEnabled == 0)
		{
			PRINT_KERNEL_PATCH_MSG(L"    Failed to find g_CiEnabled.\r\n");
			return EFI_NOT_FOUND;
		}
	}

	PRINT_KERNEL_PATCH_MSG(L"== Disassembling PAGE to find nt!SeValidateImageData '%S' ==\r\n",
		(BuildNumber >= 9200 ? L"mov eax, 0xC0000428" : L"cmp g_CiEnabled, al"));
	UINT8 *SeValidateImageDataMovEaxAddress = NULL, *SeValidateImageDataJzAddress = NULL;

	// Start decode loop
	Context.Length = PageSizeOfRawData;
	Context.Offset = 0;
	while ((Context.InstructionAddress = (ZyanU64)(PageStartVa + Context.Offset),
			Status = ZydisDecoderDecodeFull(&Context.Decoder,
											(VOID*)Context.InstructionAddress,
											Context.Length - Context.Offset,
											&Context.Instruction,
											Context.Operands)) != ZYDIS_STATUS_NO_MORE_DATA)
	{
		if (!ZYAN_SUCCESS(Status))
		{
			Context.Offset++;
			continue;
		}

		// On Windows >= 8, check if this is 'mov eax, 0xC0000428' (STATUS_INVALID_IMAGE_HASH) in SeValidateImageData
		if ((BuildNumber >= 9200 &&
			(Context.Instruction.operand_count == 2 && Context.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV) &&
			(Context.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Context.Operands[0].reg.value == ZYDIS_REGISTER_EAX) &&
			Context.Operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && (Context.Operands[1].imm.value.s & 0xFFFFFFFFLL) == 0xc0000428LL))
		{
			// Exclude false positives: next instruction must be jmp rel32 (Win 8), jmp rel8 (Win 8.1/10) or ret
			CONST UINT8* Address = (UINT8*)Context.InstructionAddress;
			CONST UINT8 JmpOpcode = BuildNumber >= 9600 ? 0xEB : 0xE9;
			if (*(Address + Context.Instruction.length) == JmpOpcode || *(Address + Context.Instruction.length) == 0xC3)
			{
				SeValidateImageDataMovEaxAddress = (UINT8*)Address;
				PRINT_KERNEL_PATCH_MSG(L"    Found 'mov eax, 0xC0000428' in SeValidateImageData [RVA: 0x%X].\r\n",
					(UINT32)(SeValidateImageDataMovEaxAddress - ImageBase));
				break;
			}
		}
		// On Windows Vista/7, check if this is 'cmp g_CiEnabled, al' in SeValidateImageData
		else if (BuildNumber < 9200 &&
			(Context.Instruction.operand_count == 3 && Context.Instruction.mnemonic == ZYDIS_MNEMONIC_CMP) &&
			(Context.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && Context.Operands[0].mem.base == ZYDIS_REGISTER_RIP) &&
			(Context.Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && Context.Operands[1].reg.value == ZYDIS_REGISTER_AL))
		{
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &OperandAddress)) &&
				OperandAddress == gCiEnabled)
			{
				// Verify the next instruction is jz, and store its address instead of the cmp, as we will be patching the jz
				CONST UINT8* Address = (UINT8*)Context.InstructionAddress;
				if (*(Address + Context.Instruction.length) == 0x74)
				{
					SeValidateImageDataJzAddress = (UINT8*)(Address + Context.Instruction.length);
					PRINT_KERNEL_PATCH_MSG(L"    Found 'cmp g_CiEnabled, al' in SeValidateImageData [RVA: 0x%X].\r\n",
						(UINT32)(Address - ImageBase));
					break;
				}
			}
		}

		Context.Offset += Context.Instruction.length;
	}

	if (SeValidateImageDataMovEaxAddress == NULL && SeValidateImageDataJzAddress == NULL)
	{
		PRINT_KERNEL_PATCH_MSG(L"    Failed to find SeValidateImageData '%S' pattern.\r\n",
			(BuildNumber >= 9200 ? L"mov eax, 0xC0000428" : L"cmp g_CiEnabled, al"));
		return EFI_NOT_FOUND;
	}

	// We have all the addresses we need; now do the actual patching.
	// SepInitializeCodeIntegrity is only patched when using the 'nuke option' DSE_DISABLE_AT_BOOT.
	if (BypassType == DSE_DISABLE_AT_BOOT)
	{
		CONST UINT16 ZeroEcx = 0xC931;
		CopyWpMem(SepInitializeCodeIntegrityMovEcxAddress, &ZeroEcx, sizeof(ZeroEcx));					// xor ecx, ecx
	}

	// SeValidateImageData *must* be patched on Windows Vista and 7 regardless of the DSE bypass method.
	// On Windows >= 8, again require DSE_DISABLE_AT_BOOT to do anything as it is otherwise harmless.
	if (BuildNumber < 9200)
		SetWpMem(SeValidateImageDataJzAddress, sizeof(UINT8), 0xEB);									// jmp
	else if (BypassType == DSE_DISABLE_AT_BOOT)
	{
		CONST UINT32 Zero = 0;
		CopyWpMem(SeValidateImageDataMovEaxAddress + 1 /*skip existing mov*/, &Zero, sizeof(Zero));		// mov eax, 0
	}

	if (BuildNumber >= 16299 && BypassType == DSE_DISABLE_AT_BOOT)
	{
		// We are on RS3 or higher. If we can find and patch SeCodeIntegrityQueryInformation, great.
		// But DSE has been disabled at this point, so success will be returned regardless.
		UINT8* Found = NULL;
		CONST EFI_STATUS CiStatus = FindPattern(SigSeCodeIntegrityQueryInformation,
												0xCC,
												sizeof(SigSeCodeIntegrityQueryInformation),
												(VOID*)PageStartVa, // SeCodeIntegrityQueryInformation is in PAGE, so start there
												PageSizeOfRawData,
												(VOID**)&Found);
		if (EFI_ERROR(CiStatus))
		{
			PRINT_KERNEL_PATCH_MSG(L"\r\nFailed to find SeCodeIntegrityQueryInformation. Skipping patch.\r\n");
		}
		else
		{
			CopyMem(Found, SeCodeIntegrityQueryInformationPatch, sizeof(SeCodeIntegrityQueryInformationPatch));
			PRINT_KERNEL_PATCH_MSG(L"\r\nPatched SeCodeIntegrityQueryInformation [RVA: 0x%X].\r\n", (UINT32)(Found - ImageBase));
		}
	}

	return EFI_SUCCESS;
}

//
// Patches ntoskrnl.exe
//
EFI_STATUS
EFIAPI
PatchNtoskrnl(
	IN VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ntoskrnl.exe at 0x%llX, size 0x%llX\r\n", (UINTN)ImageBase, (UINTN)NtHeaders->OptionalHeader.SizeOfImage);

	// Print file and version info
	UINT16 MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;
	UINT32 FileFlags = 0;
	EFI_STATUS Status = GetPeFileVersionInfo(ImageBase, &MajorVersion, &MinorVersion, &BuildNumber, &Revision, &FileFlags);
	if (EFI_ERROR(Status))
	{
		PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] WARNING: failed to obtain ntoskrnl.exe version info. Status: %llx\r\n", Status);
	}
	else
	{
		PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] Patching ntoskrnl.exe v%u.%u.%u.%u...\r\n", MajorVersion, MinorVersion, BuildNumber, Revision);
		gKernelPatchInfo.KernelBuildNumber = BuildNumber;

		// Check if this is a supported kernel version. All versions after Vista SP1 should be supported.
		// There is no "maximum allowed" version; e.g. 10.1, 11.0... are OK. Windows 10 is a whole three major versions higher than Windows 7,
		// and the only real changes were an added spyware bundle and the removal of the classic theme. Seriously, fuck whoever did that
		if (BuildNumber < 6001)
		{
			PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ERROR: Unsupported kernel image version.\r\n");
			return EFI_UNSUPPORTED;
		}
		
		if ((FileFlags & VS_FF_DEBUG) != 0)
		{
			// Do not patch checked kernels. There is too much difference in PG and DSE initialization code due to missing optimizations.
			// This is a moot point anyway because MS has stopped releasing checked OS builds or even kernels to common plebs (i.e. not Intel or Nvidia)
			PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] ERROR: Checked kernels are not supported.\r\n");
			return EFI_UNSUPPORTED;
		}
	}

	// Find the INIT and PAGE sections
	PEFI_IMAGE_SECTION_HEADER InitSection = NULL, TextSection = NULL, PageSection = NULL;
	PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
		CopyMem(SectionName, Section->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
		SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';

		if (AsciiStrCmp(SectionName, "INIT") == 0)
			InitSection = Section;
		else if (AsciiStrCmp(SectionName, ".text") == 0)
			TextSection = Section;
		else if (AsciiStrCmp(SectionName, "PAGE") == 0)
			PageSection = Section;

		Section++;
	}

	ASSERT(InitSection != NULL && TextSection != NULL && PageSection != NULL);

	// Patch INIT and .text sections to disable PatchGuard
	PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] Disabling PatchGuard... [INIT RVA: 0x%X - 0x%X]\r\n",
		InitSection->VirtualAddress, InitSection->VirtualAddress + InitSection->SizeOfRawData);
	Status = DisablePatchGuard(ImageBase,
								NtHeaders,
								InitSection,
								TextSection,
								BuildNumber);
	if (EFI_ERROR(Status))
		return Status;

	PRINT_KERNEL_PATCH_MSG(L"\r\n[PatchNtoskrnl] Successfully disabled PatchGuard.\r\n");

	if (gDriverConfig.DseBypassMethod == DSE_DISABLE_AT_BOOT ||
		(BuildNumber < 9200 && gDriverConfig.DseBypassMethod != DSE_DISABLE_NONE))
	{
		// Patch PAGE section to disable DSE at boot, or (on Windows Vista/7) to allow the SetVariable hook to be safely used more than once
		PRINT_KERNEL_PATCH_MSG(L"[PatchNtoskrnl] %S... [PAGE RVA: 0x%X - 0x%X]\r\n",
			gDriverConfig.DseBypassMethod == DSE_DISABLE_AT_BOOT ? L"Disabling DSE" : L"Ensuring safe DSE bypass",
			PageSection->VirtualAddress, PageSection->VirtualAddress + PageSection->SizeOfRawData);
		Status = DisableDSE(ImageBase,
							NtHeaders,
							PageSection,
							gDriverConfig.DseBypassMethod,
							BuildNumber);
		if (EFI_ERROR(Status))
			return Status;

		if (gDriverConfig.DseBypassMethod == DSE_DISABLE_AT_BOOT)
			PRINT_KERNEL_PATCH_MSG(L"\r\n[PatchNtoskrnl] Successfully disabled DSE.\r\n");
	}

	return Status;
}
