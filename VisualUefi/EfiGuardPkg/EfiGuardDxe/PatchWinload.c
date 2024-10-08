#include "EfiGuardDxe.h"
#include "mapper.h"
#include <Guid/Acpi.h>
#include <Library/BaseMemoryLib.h>

t_OslFwpKernelSetupPhase1 gOriginalOslFwpKernelSetupPhase1 = NULL;
UINT8 gOslFwpKernelSetupPhase1Backup[sizeof(gHookTemplate)] = { 0 };
BL_IMG_ALLOCATE_IMAGE_BUFFER gOriginalBlImgAllocateImageBuffer = NULL;
UINT8 gBlImgAllocateImageBufferBackup[sizeof(gHookTemplate)] = { 0 };

// Signature for winload!OslFwpKernelSetupPhase1+XX, where the value of XX needs to be determined by backtracking.
// Windows 10 RS4 and later only. On older OSes, and on Windows 10 as fallback, OslFwpKernelSetupPhase1 is found via xrefs to EfipGetRsdt
STATIC CONST UINT8 SigOslFwpKernelSetupPhase1[] = {
	0x89, 0xCC, 0x24, 0x01, 0x00, 0x00,				// mov [REG+124h], r32
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,					// call BlBdStop
	0xCC, 0x8B, 0xCC								// mov r32, r/m32
};

STATIC UNICODE_STRING ImgpFilterValidationFailureMessage = RTL_CONSTANT_STRING(L"*** Windows is unable to verify the signature of"); // newline, etc etc...

// Signature for winload!BlStatusPrint. This is only needed if winload.efi does not export it (RS4 and earlier)
// Windows 10 only. I could find a universal signature for this, but I rarely need the debugger output anymore...
STATIC CONST UINT8 SigBlStatusPrint[] = {
	0x48, 0x8B, 0xC4,								// mov rax, rsp
	0x48, 0x89, 0x48, 0x08,							// mov [rax+8], rcx
	0x48, 0x89, 0x50, 0x10,							// mov [rax+10h], rdx
	0x4C, 0x89, 0x40, 0x18,							// mov [rax+18h], r8
	0x4C, 0x89, 0x48, 0x20,							// mov [rax+20h], r9
	0x53,											// push rbx
	0x48, 0x83, 0xEC, 0x40,							// sub rsp, 40h
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,					// call BlBdDebuggerEnabled
	0x84, 0xC0,										// test al, al
	0x74, 0xCC										// jz XX
};

// EFI vendor GUID used by Microsoft
STATIC CONST EFI_GUID MicrosoftVendorGuid = {
	0x77fa9abd, 0x0359, 0x4d32, { 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b }
};

// EFI variable used to set VBS enablement. Set by SecConfig.efi when disabling VBS/IUM,
// read (and then deleted) by winload.efi during boot
STATIC CONST CHAR16 VbsPolicyDisabledVariableName[] = L"VbsPolicyDisabled";


NTSTATUS
EFIAPI
BlStatusPrintNoop(
	IN CONST CHAR16 *Format,
	...
	)
{
	return (NTSTATUS)0xC00000BBL; // STATUS_NOT_SUPPORTED
}

t_BlStatusPrint gBlStatusPrint = BlStatusPrintNoop;

//
// Gets a loaded module entry from the boot loader's LoadOrderList
//
STATIC
PKLDR_DATA_TABLE_ENTRY
EFIAPI
GetBootLoadedModule(
	IN CONST LIST_ENTRY* LoadOrderListHead,
	IN CONST CHAR16* ModuleName
	)
{
	if (ModuleName == NULL || LoadOrderListHead == NULL)
		return NULL;

	for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink; ListEntry != LoadOrderListHead; ListEntry = ListEntry->ForwardLink)
	{
		// This is fairly heavy abuse of CR(), but legal C because (only) the first field of a struct is guaranteed to be at offset 0 (C99 6.7.2.1, point 13)
		CONST PBLDR_DATA_TABLE_ENTRY Entry = (PBLDR_DATA_TABLE_ENTRY)BASE_CR(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (Entry != NULL && StrniCmp(Entry->KldrEntry.BaseDllName.Buffer, ModuleName, (Entry->KldrEntry.BaseDllName.Length / sizeof(CHAR16))) == 0)
			return &Entry->KldrEntry;
	}
	return NULL;
}

//
// Disables VBS for this boot
//
STATIC
EFI_STATUS
EFIAPI
DisableVbs(
	VOID
	)
{
	CONST BOOLEAN Disabled = TRUE;
	UINT32 Attributes;
	UINTN Size = 0;

	// Clear VbsPolicyDisabled variable if needed
	EFI_STATUS Status = gRT->GetVariable((CHAR16*)VbsPolicyDisabledVariableName,
										(EFI_GUID*)&MicrosoftVendorGuid,
										&Attributes,
										&Size,
										NULL);
	if (Status != EFI_NOT_FOUND &&
		(Attributes != (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS) || Size != sizeof(Disabled)))
	{
		gRT->SetVariable((CHAR16*)VbsPolicyDisabledVariableName,
						(EFI_GUID*)&MicrosoftVendorGuid,
						0,
						0,
						NULL);
	}

	// Write the new value
	Status = gRT->SetVariable((CHAR16*)VbsPolicyDisabledVariableName,
							(EFI_GUID*)&MicrosoftVendorGuid,
							EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
							sizeof(Disabled),
							(BOOLEAN*)&Disabled);
	return Status;
}


struct {
	VOID* AllocatedBuffer;
	EFI_STATUS AllocatedBufferStatus;
} mapper = { NULL };


//
// winload!BlImgAllocateImageBuffer hook
//

EFI_STATUS EFIAPI BlImgAllocateImageBufferHook(
	VOID** imageBuffer,
	UINTN imageSize,
	UINT32 memoryType,
	UINT32 attributes, VOID* unused,
	UINT32 flags)
{
	// Restore the original function bytes that we replaced with our hook
	CopyWpMem((VOID*)gOriginalBlImgAllocateImageBuffer, gBlImgAllocateImageBufferBackup, sizeof(gHookTemplate));

	EFI_STATUS status = gOriginalBlImgAllocateImageBuffer(
		imageBuffer, imageSize, memoryType, attributes, unused, flags);


	if (!EFI_ERROR(status) && memoryType == BL_MEMORY_TYPE_APPLICATION) {
		mapper.AllocatedBufferStatus = gOriginalBlImgAllocateImageBuffer(
			&mapper.AllocatedBuffer, MAPPER_BUFFER_SIZE, memoryType,
			BL_MEMORY_ATTRIBUTE_RWX, unused, 0);

		if (EFI_ERROR(mapper.AllocatedBufferStatus)) {
			mapper.AllocatedBuffer = NULL;
		}
		else
		{
			PRINT_KERNEL_PATCH_MSG(L"Alloc Application Memory Success !!!!!!! \n");
		}
		// Don't hook the function again
		return status;
	}

	// 再次hook
	CONST UINTN BlImgAllocateImageBufferHookAddress = (UINTN)&BlImgAllocateImageBufferHook;
	CopyWpMem((VOID*)gOriginalBlImgAllocateImageBuffer, gHookTemplate, sizeof(gHookTemplate));
	CopyWpMem((UINT8*)gOriginalBlImgAllocateImageBuffer + gHookTemplateAddressOffset,
		(UINTN*)&BlImgAllocateImageBufferHookAddress, sizeof(BlImgAllocateImageBufferHookAddress));
	return status;

}

EFI_STATUS
EFIAPI
UMap_HookBlImgAllocateImageBuffer(
	IN VOID* ImageBase,
	UINT32 ImageSize
)
{
	VOID* funcCall =
		UMap_FindPattern(ImageBase, ImageSize,
			"\xE8\x00\x00\x00\x00\x4c\x8b\x65\xc7", "x????xxxx");

	if (!funcCall) {
		Print(L"！！！Failed to find BlImgAllocateImageBuffer\n");
		gBS->Stall(SEC_TO_MICRO(2));
	}
	else
	{
		Print(L"BlImgAllocateImageBuffer Found :)\n");
	}

	CONST UINTN BlImgAllocateImageBufferHookAddress = (UINTN)&BlImgAllocateImageBufferHook;
	CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL); // Note: implies cli
	// Backup original function prologue
	gOriginalBlImgAllocateImageBuffer = (BL_IMG_ALLOCATE_IMAGE_BUFFER)RELATIVE_ADDR(funcCall, 5);
	CopyMem(gBlImgAllocateImageBufferBackup, (VOID*)gOriginalBlImgAllocateImageBuffer, sizeof(gHookTemplate));
	// Place faux call (push addr, ret) at the start of the function to transfer execution to our hook
	CopyWpMem((VOID*)gOriginalBlImgAllocateImageBuffer, gHookTemplate, sizeof(gHookTemplate));
	CopyWpMem((UINT8*)gOriginalBlImgAllocateImageBuffer + gHookTemplateAddressOffset,
		(UINTN*)&BlImgAllocateImageBufferHookAddress, sizeof(BlImgAllocateImageBufferHookAddress));
	gBS->RestoreTPL(Tpl);

	//BlImgAllocateImageBuffer = (BL_IMG_ALLOCATE_IMAGE_BUFFER)UMap_TrampolineHook(
	//	(VOID*)BlImgAllocateImageBufferHook, RELATIVE_ADDR(funcCall, 5),
	//	BlImgAllocateImageBufferOriginal);
	return 0;
}

EFI_STATUS EFIAPI MapMapper(VOID* ntoskrnlBase, VOID** entryPoint,
	VOID* targetFunction)
{
	UINT8* mapperBase = mapper.AllocatedBuffer;
	UINT8* mapperBuffer = MAPPER_BUFFER;

	IMAGE_NT_HEADERS64* ntHeaders =
		(IMAGE_NT_HEADERS64*)(mapperBuffer +
			((IMAGE_DOS_HEADER*)mapperBuffer)->e_lfanew);

	// Map headers
	UMap_MemCopy(mapperBase, mapperBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

	// Map sections
	IMAGE_SECTION_HEADER* sections =
		(IMAGE_SECTION_HEADER*)((UINT8*)&ntHeaders->OptionalHeader +
			ntHeaders->FileHeader.SizeOfOptionalHeader);

	for (UINT16 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER* section = &sections[i];
		if (section->SizeOfRawData) {
			UMap_MemCopy(mapperBase + section->VirtualAddress,
				mapperBuffer + section->PointerToRawData,
				section->SizeOfRawData);
		}
	}

	// Resolve ntoskrnl imports
	UINT32 importsRva =
		ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
		.VirtualAddress;

	if (importsRva)
	{
		IMAGE_IMPORT_DESCRIPTOR* importDescriptor =
			(IMAGE_IMPORT_DESCRIPTOR*)(mapperBase + importsRva);

		for (; importDescriptor->FirstThunk; ++importDescriptor)
		{
			IMAGE_THUNK_DATA64* thunk =
				(IMAGE_THUNK_DATA64*)(mapperBase +
					importDescriptor->FirstThunk);

			IMAGE_THUNK_DATA64* thunkOriginal =
				(IMAGE_THUNK_DATA64*)(mapperBase +
					importDescriptor->u.OriginalFirstThunk);

			for (; thunk->u1.AddressOfData; ++thunk, ++thunkOriginal)
			{
				UINT64 import = UMap_GetExport(
					ntoskrnlBase,
					((IMAGE_IMPORT_BY_NAME*)(mapperBase +
						thunkOriginal->u1.AddressOfData))
					->Name);

				if (!import)
				{
					return EFI_NOT_FOUND;
				}

				thunk->u1.Function = import;
			}
		}
	}

	// Resolve relocations
	IMAGE_DATA_DIRECTORY* baseRelocDir =
		&ntHeaders->OptionalHeader
		.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (baseRelocDir->VirtualAddress)
	{
		IMAGE_BASE_RELOCATION* reloc =
			(IMAGE_BASE_RELOCATION*)(mapperBase +
				baseRelocDir->VirtualAddress);

		for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size;)
		{
			UINT32 relocCount =
				(reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
				sizeof(UINT16);

			UINT16* relocData =
				(UINT16*)((UINT8*)reloc + sizeof(IMAGE_BASE_RELOCATION));

			UINT8* relocBase = mapperBase + reloc->VirtualAddress;

			for (UINT32 i = 0; i < relocCount; ++i, ++relocData)
			{
				UINT16 data = *relocData;
				UINT16 type = data >> 12;
				UINT16 offset = data & 0xFFF;

				switch (type) {
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_DIR64: {
					UINT64* rva = (UINT64*)(relocBase + offset);
					*rva =
						(UINT64)(mapperBase +
							(*rva - ntHeaders->OptionalHeader.ImageBase));
					break;
				}
				default:
					return EFI_UNSUPPORTED;
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = (IMAGE_BASE_RELOCATION*)relocData;
		}
	}

	// Copy mapper data
	UINT32 exportsRva =
		ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.VirtualAddress;

	if (exportsRva) {
		IMAGE_EXPORT_DIRECTORY* exports =
			(IMAGE_EXPORT_DIRECTORY*)(mapperBase + exportsRva);

		if (exports->NumberOfNames) {
			UINT32* funcRva =
				(UINT32*)(mapperBase + exports->AddressOfFunctions);

			UINT16* ordinalRva =
				(UINT16*)(mapperBase + exports->AddressOfNameOrdinals);

			UMap_MemCopy(mapperBase + funcRva[ordinalRva[0]], targetFunction,
				MAPPER_DATA_SIZE);
		}
	}

	*entryPoint = mapperBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
	return EFI_SUCCESS;
}

EFI_STATUS EFIAPI SetupMapper(KLDR_DATA_TABLE_ENTRY* ntoskrnl,
	KLDR_DATA_TABLE_ENTRY* targetModule)
{
	VOID* mapperEntryPoint;
	EFI_STATUS status = MapMapper(ntoskrnl->DllBase, &mapperEntryPoint,
		targetModule->EntryPoint);

	if (EFI_ERROR(status)) {
		return status;
	}

	// This is necessary because on <1903 the kernel will remap boot-time
	// drivers and recalculate their DriverEntry, so you cannot simply change
	// the pointer or do a standard trampoline hook and store the pointer in
	// mapper data as it will point to invalid memory after the kernel
	// initializes

	UMap_MemCopy(targetModule->EntryPoint, "\x4C\x8D\x05\xF9\xFF\xFF\xFF", // lea r8, [rip - 7]
		7);
	
	UMap_TrampolineHook(mapperEntryPoint, (UINT8*)targetModule->EntryPoint + 7,
		NULL);

	return EFI_SUCCESS;
}

//
// winload.efi!OslFwpKernelSetupPhase1 hook to patch ntoskrnl.exe
//
EFI_STATUS
EFIAPI
HookedOslFwpKernelSetupPhase1(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	)
{
	// Restore the original function bytes that we replaced with our hook
	CopyWpMem((VOID*)gOriginalOslFwpKernelSetupPhase1, gOslFwpKernelSetupPhase1Backup, sizeof(gHookTemplate));

	UINT8* LoadOrderListHeadAddress = (UINT8*)&LoaderBlock->LoadOrderListHead;
	if (gKernelPatchInfo.WinloadBuildNumber < 7600)
	{
		// We are booting Vista or some other fossil, which means that our LOADER_PARAMETER_BLOCK declaration in no way matches what is
		// actually being passed by the loader. Notably, the first four UINT32 fields are absent, so fix up the list entry pointer.
		LoadOrderListHeadAddress -= FIELD_OFFSET(LOADER_PARAMETER_BLOCK, LoadOrderListHead);
	}

	// Get the kernel entry from the loader block's LoadOrderList
	KLDR_DATA_TABLE_ENTRY* KernelEntry = GetBootLoadedModule((LIST_ENTRY*)LoadOrderListHeadAddress, L"ntoskrnl.exe");
	if (KernelEntry == NULL)
	{
		gKernelPatchInfo.Status = EFI_LOAD_ERROR;
		PRINT_KERNEL_PATCH_MSG(L"[HookedOslFwpKernelSetupPhase1] Failed to find ntoskrnl.exe in LoadOrderList!\r\n");
		goto CallOriginal;
	}

	// hook acpiex.sys 入口点
	if (mapper.AllocatedBuffer)
	{
		/*KLDR_DATA_TABLE_ENTRY* targetModule = UMap_GetModuleEntry(
			&LoaderBlock->LoadOrderListHead, L"acpiex.sys");*/

		KLDR_DATA_TABLE_ENTRY* targetModule = UMap_GetModuleEntry(
			&LoaderBlock->LoadOrderListHead, L"disk.sys");

		if (targetModule)
		{
			PRINT_KERNEL_PATCH_MSG(L"----------------------Found disk.sys ;)\n");

			EFI_STATUS sc = SetupMapper(KernelEntry, targetModule);
			if (sc == EFI_SUCCESS)
			{
				PRINT_KERNEL_PATCH_MSG(L"----------------------Map Success ;)\n");
			}
		}
	}

	VOID* KernelBase = KernelEntry->DllBase;
	CONST UINT32 KernelSize = KernelEntry->SizeOfImage;
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = KernelBase != NULL && KernelSize > 0
		? RtlpImageNtHeaderEx(KernelBase, (UINTN)KernelSize)
		: NULL;
	if (KernelBase == NULL || KernelSize == 0)
	{
		gKernelPatchInfo.Status = EFI_NOT_FOUND;
		PRINT_KERNEL_PATCH_MSG(L"[HookedOslFwpKernelSetupPhase1] Kernel image at 0x%p with size 0x%lx is invalid!\r\n", KernelBase, KernelSize);
		goto CallOriginal;
	}

	// Patch the kernel
	gKernelPatchInfo.KernelBase = KernelBase;
	gKernelPatchInfo.Status = PatchNtoskrnl(KernelBase,
											NtHeaders);

CallOriginal:
	// No error handling here (not a lot of options). This is done in the ExitBootServices() callback which reads the patch status

	// Call the original function to transfer execution back to winload!OslFwpKernelSetupPhase1
	return gOriginalOslFwpKernelSetupPhase1(LoaderBlock);
}

//
// Patches ImgpValidateImageHash in bootmgfw.efi, bootmgr.efi, and winload.[efi|exe] to allow loading modified kernels and boot loaders.
// Failures are ignored because this patch is not needed for the bootkit to work
//
EFI_STATUS
EFIAPI
PatchImgpValidateImageHash(
	IN INPUT_FILETYPE FileType,
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	// This works on pretty much anything really
	ASSERT(FileType == WinloadExe || FileType == BootmgfwEfi || FileType == BootmgrEfi || FileType == WinloadEfi);
	CONST CHAR16* ShortName = FileType == BootmgfwEfi ? L"bootmgfw" : (FileType == BootmgrEfi ? L"bootmgr" : L"winload");

	CONST PEFI_IMAGE_SECTION_HEADER CodeSection = IMAGE_FIRST_SECTION(NtHeaders);

	CONST UINT32 CodeSizeOfRawData = CodeSection->SizeOfRawData;
	CONST UINT8* CodeStartVa = ImageBase + CodeSection->VirtualAddress;

	Print(L"== Disassembling .text to find %S!ImgpValidateImageHash ==\r\n", ShortName);
	UINT8* AndMinusFortyOneAddress = NULL;

	// Initialize Zydis
	ZYDIS_CONTEXT Context;
	ZyanStatus Status = ZydisInit(NtHeaders, &Context);
	if (!ZYAN_SUCCESS(Status))
	{
		Print(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	Context.Length = CodeSizeOfRawData;
	Context.Offset = 0;

	// Start decode loop
	while ((Context.InstructionAddress = (ZyanU64)(CodeStartVa + Context.Offset),
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

		// Check if this is 'and REG32, 0FFFFFFD7h' (only esi and r8d are used here really)
		if (Context.Instruction.operand_count == 3 &&
			(Context.Instruction.length == 3 || Context.Instruction.length == 4) &&
			Context.Instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
			Context.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			Context.Operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			Context.Operands[1].imm.is_signed == ZYAN_TRUE &&
			Context.Operands[1].imm.value.s == (ZyanI64)((ZyanI32)0xFFFFFFD7)) // Sign extend to 64 bits
		{
			AndMinusFortyOneAddress = (UINT8*)Context.InstructionAddress;
			break;
		}

		Context.Offset += Context.Instruction.length;
	}

	// Backtrack to function start
	UINT8* ImgpValidateImageHash = BacktrackToFunctionStart(ImageBase, NtHeaders, AndMinusFortyOneAddress);
	if (ImgpValidateImageHash == NULL)
	{
		Print(L"    Failed to find %S!ImgpValidateImageHash%S.\r\n",
			ShortName, (AndMinusFortyOneAddress == NULL ? L" 'and xxx, 0FFFFFFD7h' instruction" : L""));
		return EFI_NOT_FOUND;
	}

	// Apply the patch
	CONST UINT32 Ok = 0xC3C033; // xor eax, eax, ret
	CopyWpMem(ImgpValidateImageHash, &Ok, sizeof(Ok));

	// Print info
	Print(L"    Patched %S!ImgpValidateImageHash [RVA: 0x%X].\r\n",
		ShortName, (UINT32)(ImgpValidateImageHash - ImageBase));

	return EFI_SUCCESS;
}

//
// Patches ImgpFilterValidationFailure in bootmgfw.efi, bootmgr.efi, and winload.[efi|exe]
// Failures are ignored because this patch is not needed for the bootkit to work
//
EFI_STATUS
EFIAPI
PatchImgpFilterValidationFailure(
	IN INPUT_FILETYPE FileType,
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	// This works on pretty much anything really
	ASSERT(FileType == WinloadExe || FileType == BootmgfwEfi || FileType == BootmgrEfi || FileType == WinloadEfi);
	CONST CHAR16* ShortName = FileType == BootmgfwEfi ? L"bootmgfw" : (FileType == BootmgrEfi ? L"bootmgr" : L"winload");

	// Find .text and/or .rdata sections
	PEFI_IMAGE_SECTION_HEADER PatternSection = NULL, CodeSection = NULL;
	PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (CompareMem(Section->Name, ".text", sizeof(".text") - 1) == 0)
			CodeSection = Section;
		if (((FileType == BootmgfwEfi || FileType == BootmgrEfi) &&
			CompareMem(Section->Name, ".text", sizeof(".text") - 1) == 0) // [bootmgfw|bootmgr].efi (usually) has no .rdata section, and starting at .text is always fine
			||
			((FileType == WinloadExe || FileType == WinloadEfi) &&
			CompareMem(Section->Name, ".rdata", sizeof(".rdata") - 1) == 0)) // For winload.[exe|efi] the string is in .rdata
			PatternSection = Section;
		Section++;
	}

	ASSERT(PatternSection != NULL);
	ASSERT(CodeSection != NULL);

	CONST UINT32 PatternStartRva = PatternSection->VirtualAddress;
	CONST UINT32 PatternSizeOfRawData = PatternSection->SizeOfRawData;
	CONST UINT8* PatternStartVa = ImageBase + PatternStartRva;

	CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
	CopyMem(SectionName, PatternSection->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
	SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';
	Print(L"\r\n== Searching for load failure string in %a [RVA: 0x%X - 0x%X] ==\r\n",
		SectionName, PatternStartRva, PatternStartRva + PatternSizeOfRawData);

	// Search for the black screen of death string "Windows is unable to verify the integrity of the file [...]"
	UINT8* IntegrityFailureStringAddress = NULL;
	for (UINT8* Address = (UINT8*)PatternStartVa;
		Address < ImageBase + NtHeaders->OptionalHeader.SizeOfImage - ImgpFilterValidationFailureMessage.MaximumLength;
		++Address)
	{
		if (CompareMem(Address, ImgpFilterValidationFailureMessage.Buffer, ImgpFilterValidationFailureMessage.Length) == 0)
		{
			IntegrityFailureStringAddress = Address;
			Print(L"    Found load failure string at 0x%llx.\r\n", (UINTN)IntegrityFailureStringAddress);
			break;
		}
	}

	if (IntegrityFailureStringAddress == NULL)
	{
		Print(L"    Failed to find load failure string.\r\n");
		return EFI_NOT_FOUND;
	}

	CONST UINT32 CodeStartRva = CodeSection->VirtualAddress;
	CONST UINT32 CodeSizeOfRawData = CodeSection->SizeOfRawData;
	CONST UINT8* CodeStartVa = ImageBase + CodeStartRva;

	ZeroMem(SectionName, sizeof(SectionName));
	CopyMem(SectionName, CodeSection->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
	Print(L"== Disassembling %a to find %S!ImgpFilterValidationFailure ==\r\n", SectionName, ShortName);
	UINT8* LeaIntegrityFailureAddress = NULL;

	// Initialize Zydis
	ZYDIS_CONTEXT Context;
	ZyanStatus Status = ZydisInit(NtHeaders, &Context);
	if (!ZYAN_SUCCESS(Status))
	{
		Print(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	Context.Length = CodeSizeOfRawData;
	Context.Offset = 0;

	// Start decode loop
	while ((Context.InstructionAddress = (ZyanU64)(CodeStartVa + Context.Offset),
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

		// Check if this is "lea REG, ds:[rip + offset_to_bsod_string]"
		if (Context.Instruction.operand_count == 2 && Context.Instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			Context.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			Context.Operands[1].mem.base == ZYDIS_REGISTER_RIP)
		{
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[1], Context.InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)IntegrityFailureStringAddress)
			{
				LeaIntegrityFailureAddress = (UINT8*)Context.InstructionAddress;
				Print(L"    Found load instruction for load failure string at 0x%llx.\r\n", (UINTN)LeaIntegrityFailureAddress);
				break;
			}
		}

		Context.Offset += Context.Instruction.length;
	}

	// Backtrack to function start
	UINT8* ImgpFilterValidationFailure = BacktrackToFunctionStart(ImageBase, NtHeaders, LeaIntegrityFailureAddress);
	if (ImgpFilterValidationFailure == NULL)
	{
		Print(L"    Failed to find %S!ImgpFilterValidationFailure%S.\r\n",
			ShortName, (LeaIntegrityFailureAddress == NULL ? L" load failure string load instruction" : L""));
		return EFI_NOT_FOUND;
	}

	// Apply the patch
	CONST UINT32 Ok = 0xC3C033; // xor eax, eax, ret
	CopyWpMem(ImgpFilterValidationFailure, &Ok, sizeof(Ok));

	// Print info
	Print(L"    Patched %S!ImgpFilterValidationFailure [RVA: 0x%X].\r\n\r\n",
		ShortName, (UINT32)(ImgpFilterValidationFailure - ImageBase));

	return EFI_SUCCESS;
}

//
// Finds OslFwpKernelSetupPhase1 in winload.efi
//
EFI_STATUS
EFIAPI
FindOslFwpKernelSetupPhase1(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN PEFI_IMAGE_SECTION_HEADER CodeSection,
	IN PEFI_IMAGE_SECTION_HEADER PatternSection,
	IN UINT16 BuildNumber,
	OUT UINT8** OslFwpKernelSetupPhase1Address
	)
{
	*OslFwpKernelSetupPhase1Address = NULL;

	CONST UINT8* CodeStartVa = ImageBase + CodeSection->VirtualAddress;
	CONST UINT32 CodeSizeOfRawData = CodeSection->SizeOfRawData;
	CONST UINT8* PatternStartVa = ImageBase + PatternSection->VirtualAddress;

	if (BuildNumber >= 17134)
	{
		// On Windows 10 RS4 and later, try simple pattern matching first since it will most likely work
		UINT8* Found = NULL;
		CONST EFI_STATUS Status = FindPattern(SigOslFwpKernelSetupPhase1,
											0xCC,
											sizeof(SigOslFwpKernelSetupPhase1),
											(VOID*)CodeStartVa,
											CodeSizeOfRawData,
											(VOID**)&Found);
		if (!EFI_ERROR(Status))
		{
			// Found signature; backtrack to function start
			*OslFwpKernelSetupPhase1Address = BacktrackToFunctionStart(ImageBase, NtHeaders, Found);
			if (*OslFwpKernelSetupPhase1Address != NULL)
			{
				Print(L"\r\nFound OslFwpKernelSetupPhase1 at 0x%llX.\r\n", (UINTN)(*OslFwpKernelSetupPhase1Address));
				return EFI_SUCCESS; // Found; early out
			}
		}
	}

	// Initialize Zydis
	Print(L"\r\n== Disassembling .text to find OslFwpKernelSetupPhase1 ==\r\n");
	ZYDIS_CONTEXT Context;
	ZyanStatus Status = ZydisInit(NtHeaders, &Context);
	if (!ZYAN_SUCCESS(Status))
	{
		Print(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	CONST VOID* BlBdStop = GetProcedureAddress((UINTN)ImageBase, NtHeaders, "BlBdStop");
	if (BuildNumber >= 17134 && BlBdStop != NULL)
	{
		Context.Length = CodeSizeOfRawData;
		Context.Offset = 6;

		// Start decode loop
		while ((Context.InstructionAddress = (ZyanU64)(CodeStartVa + Context.Offset),
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

			// Check if this is 'call BlBdStop'
			if (Context.Instruction.operand_count == 4 &&
				Context.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && Context.Operands[0].imm.is_relative == ZYAN_TRUE &&
				Context.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
			{
				ZyanU64 OperandAddress = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &OperandAddress)) &&
					OperandAddress == (UINTN)BlBdStop)
				{
					// Check if the preceding instruction is 'mov [REG+124h], r32'
					CONST UINT8* CallBlBdStopAddress = (UINT8*)Context.InstructionAddress;
					if ((CallBlBdStopAddress[-6] == 0x89 || CallBlBdStopAddress[-6] == 0x8B) &&
						*(UINT32*)(&CallBlBdStopAddress[-4]) == 0x124 &&
						(*OslFwpKernelSetupPhase1Address = BacktrackToFunctionStart(ImageBase, NtHeaders, CallBlBdStopAddress)) != NULL)
					{
						Print(L"    Found OslFwpKernelSetupPhase1 at 0x%llX.\r\n\r\n", (UINTN)(*OslFwpKernelSetupPhase1Address));
						return EFI_SUCCESS;
					}
				}
			}

			Context.Offset += Context.Instruction.length;
		}
	}

	// On RS4 and later, the previous method really should have worked
	ASSERT(BuildNumber < 17134);

	// On older versions, use some convoluted but robust logic to find OslFwpKernelSetupPhase1 by matching xrefs to EfipGetRsdt.
	// This of course implies finding EfipGetRsdt first. After that, find all calls to this function, and for each, calculate
	// the distance from the start of the function to the call. OslFwpKernelSetupPhase1 is reliably (Vista through 10)
	// the function that has the smallest value for this distance, i.e. the call happens very early in the function.
	Print(L"\r\n== Searching for EfipGetRsdt pattern in .text ==\r\n");

	// Search for EFI ACPI 2.0 table GUID: { 8868e871-e4f1-11d3-bc22-0080c73c8881 }
	UINT8* PatternAddress = NULL;
	for (UINT8* Address = (UINT8*)PatternStartVa;
		Address < ImageBase + NtHeaders->OptionalHeader.SizeOfImage - sizeof(gEfiAcpi20TableGuid);
		++Address)
	{
		if (CompareGuid((CONST GUID*)Address, &gEfiAcpi20TableGuid))
		{
			PatternAddress = Address;
			Print(L"    Found EFI ACPI 2.0 GUID at 0x%llX.\r\n", (UINTN)PatternAddress);
			break;
		}
	}

	if (PatternAddress == NULL)
	{
		Print(L"    Failed to find EFI ACPI 2.0 GUID.\r\n");
		return EFI_NOT_FOUND;
	}

	Print(L"\r\n== Disassembling .text to find EfipGetRsdt ==\r\n");
	UINT8* LeaEfiAcpiTableGuidAddress = NULL;
	Context.Length = CodeSizeOfRawData;
	Context.Offset = 0;

	// Start decode loop
	while ((Context.InstructionAddress = (ZyanU64)(CodeStartVa + Context.Offset),
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

		// Check if this is "lea rcx, ds:[rip + offset_to_acpi20_guid]"
		if (Context.Instruction.operand_count == 2 && Context.Instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			Context.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			Context.Operands[0].reg.value == ZYDIS_REGISTER_RCX &&
			Context.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			Context.Operands[1].mem.base == ZYDIS_REGISTER_RIP)
		{
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[1], Context.InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)PatternAddress)
			{
				// Check for false positives (BlFwGetSystemTable)
				CONST UINT8* Check = (UINT8*)(CodeStartVa + Context.Offset - 4); // 4 = length of 'lea rdx, [r11+18h]' which precedes this instruction in EfipGetRsdt
				if (Check[0] == 0x49 && Check[1] == 0x8D && Check[2] == 0x53) // If no match, this is not EfipGetRsdt
				{
					LeaEfiAcpiTableGuidAddress = (UINT8*)Context.InstructionAddress;
					Print(L"    Found load instruction for EFI ACPI 2.0 GUID at 0x%llX.\r\n", (UINTN)LeaEfiAcpiTableGuidAddress);
					break;
				}
			}
		}

		Context.Offset += Context.Instruction.length;
	}

	if (LeaEfiAcpiTableGuidAddress == NULL)
	{
		Print(L"    Failed to find load instruction for EFI ACPI 2.0 GUID.\r\n");
		return EFI_NOT_FOUND;
	}

	CONST UINT8* EfipGetRsdt = BacktrackToFunctionStart(ImageBase, NtHeaders, LeaEfiAcpiTableGuidAddress);
	if (EfipGetRsdt == NULL)
	{
		Print(L"    Failed to find EfipGetRsdt.\r\n");
		return EFI_NOT_FOUND;
	}

	Print(L"    Found EfipGetRsdt at 0x%llX.\r\n", (UINTN)EfipGetRsdt);
	UINT8* CallEfipGetRsdtAddress = NULL;

	// Start decode loop
	Context.Offset = 0;
	UINTN ShortestDistanceToCall = MAX_UINTN;
	while ((Context.InstructionAddress = (ZyanU64)(CodeStartVa + Context.Offset),
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

		// Check if this is 'call IMM'
		if (Context.Instruction.operand_count == 4 &&
			Context.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && Context.Operands[0].imm.is_relative == ZYAN_TRUE &&
			Context.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			// Check if this is 'call EfipGetRsdt'
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Context.Instruction, &Context.Operands[0], Context.InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)EfipGetRsdt)
			{
				// Calculate the distance from the start of the function to the instruction. OslFwpKernelSetupPhase1 will always have the shortest distance
				CONST UINTN StartOfFunction = (UINTN)BacktrackToFunctionStart(ImageBase, NtHeaders, (UINT8*)Context.InstructionAddress);
				CONST UINTN Distance = Context.InstructionAddress - StartOfFunction;
				if (Distance < ShortestDistanceToCall)
				{
					CallEfipGetRsdtAddress = (UINT8*)Context.InstructionAddress;
					ShortestDistanceToCall = Distance;
				}
			}
		}

		Context.Offset += Context.Instruction.length;
	}

	if (CallEfipGetRsdtAddress == NULL)
	{
		Print(L"    Failed to find a single 'call EfipGetRsdt' instruction.\r\n");
		return EFI_NOT_FOUND;
	}

	// Found
	*OslFwpKernelSetupPhase1Address = CallEfipGetRsdtAddress - ShortestDistanceToCall;
	Print(L"    Found OslFwpKernelSetupPhase1 at 0x%llX.\r\n\r\n", (UINTN)(*OslFwpKernelSetupPhase1Address));

	return EFI_SUCCESS;
}

//
// Patches winload.efi
// 
EFI_STATUS
EFIAPI
PatchWinload(
	IN VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	// Print file and version info
	UINT16 MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;
	EFI_STATUS Status = GetPeFileVersionInfo(ImageBase, &MajorVersion, &MinorVersion, &BuildNumber, &Revision, NULL);
	if (EFI_ERROR(Status))
		Print(L"\r\nPatchWinload: WARNING: failed to obtain winload.efi version info. Status: %llx\r\n", Status);
	else
	{
		Print(L"\r\nPatching winload.efi v%u.%u.%u.%u...\r\n", MajorVersion, MinorVersion, BuildNumber, Revision);

		// Some... adjustments... need to be made later on in the case of pre-Windows 7 loader blocks, so store the build number
		gKernelPatchInfo.WinloadBuildNumber = BuildNumber;

		// Check if this is a supported winload version. All patches should work on all versions since Vista SP1,
		// except for the ImgpFilterValidationFailure patch because this function only exists on Windows 7 and higher.
		if (BuildNumber < 6001)
		{
			Print(L"\r\nPatchWinload: ERROR: Unsupported winload.efi image version.\r\n");
			Status = EFI_UNSUPPORTED;
			goto Exit;
		}
	}

	// Find the .text and .rdata sections
	PEFI_IMAGE_SECTION_HEADER CodeSection = NULL, PatternSection = NULL;
	PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
		CopyMem(SectionName, Section->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
		SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';

		if (AsciiStrCmp(SectionName, ".text") == 0)
			CodeSection = Section;
		else if (AsciiStrCmp(SectionName, ".rdata") == 0)
			PatternSection = Section;

		Section++;
	}

	ASSERT(CodeSection != NULL);
	ASSERT(PatternSection != NULL);

	if (BuildNumber >= 10240)
	{
		// (Optional) find winload!BlStatusPrint
		gBlStatusPrint = (t_BlStatusPrint)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "BlStatusPrint");
		if (gBlStatusPrint == NULL)
		{
			// Not exported (RS4 and earlier) - try to find by signature
			FindPattern(SigBlStatusPrint,
						0xCC,
						sizeof(SigBlStatusPrint),
						(UINT8*)ImageBase + CodeSection->VirtualAddress,
						CodeSection->SizeOfRawData,
						(VOID**)&gBlStatusPrint);
			if (gBlStatusPrint == NULL)
			{
				gBlStatusPrint = BlStatusPrintNoop;
				Print(L"\r\nWARNING: winload!BlStatusPrint not found. No boot debugger output will be available.\r\n");
			}
		}

		// Disable VBS for the duration of this boot
		Status = DisableVbs();
		if (EFI_ERROR(Status))
			Print(L"\r\nWARNING: failed to set EFI runtime variable \"%ls\" in order to disable VBS.\r\n", VbsPolicyDisabledVariableName);
	}

	// Find winload!OslFwpKernelSetupPhase1
	Status = FindOslFwpKernelSetupPhase1(ImageBase,
										NtHeaders,
										CodeSection,
										PatternSection,
										BuildNumber,
										(UINT8**)&gOriginalOslFwpKernelSetupPhase1);
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchWinload: failed to find OslFwpKernelSetupPhase1. Status: %llx\r\n", Status);
		goto Exit;
	}

	CONST UINTN HookedOslFwpKernelSetupPhase1Address = (UINTN)&HookedOslFwpKernelSetupPhase1;
	Print(L"HookedOslFwpKernelSetupPhase1 at 0x%p.\r\n", (VOID*)HookedOslFwpKernelSetupPhase1Address);

	CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL); // Note: implies cli

	// Backup original function prologue
	CopyMem(gOslFwpKernelSetupPhase1Backup, (VOID*)gOriginalOslFwpKernelSetupPhase1, sizeof(gHookTemplate));

	// Place faux call (push addr, ret) at the start of the function to transfer execution to our hook
	CopyWpMem((VOID*)gOriginalOslFwpKernelSetupPhase1, gHookTemplate, sizeof(gHookTemplate));
	CopyWpMem((UINT8*)gOriginalOslFwpKernelSetupPhase1 + gHookTemplateAddressOffset,
		(UINTN*)&HookedOslFwpKernelSetupPhase1Address, sizeof(HookedOslFwpKernelSetupPhase1Address));

	gBS->RestoreTPL(Tpl);

	// Patch ImgpValidateImageHash to allow custom boot loaders. This is completely
	// optional (unless booting a custom ntoskrnl.exe), and failures are ignored
	PatchImgpValidateImageHash(WinloadEfi,
								ImageBase,
								NtHeaders);

	if (BuildNumber >= 7600)
	{
		// Patch ImgpFilterValidationFailure so it doesn't silently
		// rat out every violation to a TPM or SI log. Also optional
		PatchImgpFilterValidationFailure(WinloadEfi,
										ImageBase,
										NtHeaders);
	}

Exit:
	if (EFI_ERROR(Status))
	{
		// Patch failed. Prompt user to ask what they want to do
		Print(L"\r\nPress any key to continue anyway, or press ESC to reboot.\r\n");
		if (!WaitForKey())
		{
			gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}
	else
	{
		Print(L"Successfully patched winload!OslFwpKernelSetupPhase1.\r\n");
		RtlSleep(2000);

		if (gDriverConfig.WaitForKeyPress)
		{
			Print(L"\r\nPress any key to continue.\r\n");
			WaitForKey();
		}
	}

	// Return success, because even if the patch failed, the user chose not to reboot above
	return EFI_SUCCESS;
}
