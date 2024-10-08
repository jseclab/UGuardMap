#pragma once

#include <Protocol/LoadedImage.h>

#ifndef ZYDIS_DISABLE_FORMATTER
#include <Zydis/Formatter.h>
#endif


#define CR0_WP			((UINTN)0x00010000) // CR0.WP
#define CR0_PG			((UINTN)0x80000000) // CR0.PG
#define CR4_CET			((UINTN)0x00800000) // CR4.CET
#define CR4_LA57		((UINTN)0x00001000) // CR4.LA57
#define MSR_EFER		((UINTN)0xC0000080) // Extended Function Enable Register
#define EFER_LMA		((UINTN)0x00000400) // Long Mode Active
#define EFER_UAIE		((UINTN)0x00100000) // Upper Address Ignore Enabled
#define SEC_TO_MICRO(s) ((s) * 1000000)
#define JMP_SIZE (14)
#define RELATIVE_ADDR(addr, size) ((VOID *)((UINT8 *)(addr) + *(INT32 *)((UINT8 *)(addr) + ((size) - (INT32)sizeof(INT32))) + (size)))

#define BL_MEMORY_TYPE_APPLICATION (0xE0000012)
#define BL_MEMORY_ATTRIBUTE_RWX (0x424000)
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES (16)
#define MAPPER_BUFFER_SIZE (((IMAGE_NT_HEADERS64 *)(MAPPER_BUFFER + ((IMAGE_DOS_HEADER *)MAPPER_BUFFER)->e_lfanew))->OptionalHeader.SizeOfImage)
#define CONTAINING_RECORD(address, type, field) ((type *)((UINT8 *)(address) - (UINTN)(&((type *)0)->field)))
#define IMAGE_SIZEOF_SHORT_NAME (8)
#define IMAGE_DIRECTORY_ENTRY_IMPORT (1)
#define IMAGE_DOS_SIGNATURE (0x5A4D)
#define IMAGE_DIRECTORY_ENTRY_EXPORT (0)
#define IMAGE_DIRECTORY_ENTRY_BASERELOC (5)
#define IMAGE_REL_BASED_ABSOLUTE (0)
#define IMAGE_REL_BASED_DIR64 (10)
#define MAPPER_DATA_SIZE (JMP_SIZE + 7)

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	UINT16 e_magic;                     // Magic number
	UINT16 e_cblp;                      // Bytes on last page of file
	UINT16 e_cp;                        // Pages in file
	UINT16 e_crlc;                      // Relocations
	UINT16 e_cparhdr;                   // Size of header in paragraphs
	UINT16 e_minalloc;                  // Minimum extra paragraphs needed
	UINT16 e_maxalloc;                  // Maximum extra paragraphs needed
	UINT16 e_ss;                        // Initial (relative) SS value
	UINT16 e_sp;                        // Initial SP value
	UINT16 e_csum;                      // Checksum
	UINT16 e_ip;                        // Initial IP value
	UINT16 e_cs;                        // Initial (relative) CS value
	UINT16 e_lfarlc;                    // File address of relocation table
	UINT16 e_ovno;                      // Overlay number
	UINT16 e_res[4];                    // Reserved words
	UINT16 e_oemid;                     // OEM identifier (for e_oeminfo)
	UINT16 e_oeminfo;                   // OEM information; e_oemid specific
	UINT16 e_res2[10];                  // Reserved words
	UINT32 e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER;


typedef struct _IMAGE_FILE_HEADER {
	UINT16  Machine;
	UINT16  NumberOfSections;
	UINT32  TimeDateStamp;
	UINT32  PointerToSymbolTable;
	UINT32  NumberOfSymbols;
	UINT16  SizeOfOptionalHeader;
	UINT16  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	UINT32   VirtualAddress;
	UINT32   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	UINT16               Magic;
	UINT8                MajorLinkerVersion;
	UINT8                MinorLinkerVersion;
	UINT32               SizeOfCode;
	UINT32               SizeOfInitializedData;
	UINT32               SizeOfUninitializedData;
	UINT32               AddressOfEntryPoint;
	UINT32               BaseOfCode;
	UINT64               ImageBase;
	UINT32               SectionAlignment;
	UINT32               FileAlignment;
	UINT16               MajorOperatingSystemVersion;
	UINT16               MinorOperatingSystemVersion;
	UINT16               MajorImageVersion;
	UINT16               MinorImageVersion;
	UINT16               MajorSubsystemVersion;
	UINT16               MinorSubsystemVersion;
	UINT32               Win32VersionValue;
	UINT32               SizeOfImage;
	UINT32               SizeOfHeaders;
	UINT32               CheckSum;
	UINT16               Subsystem;
	UINT16               DllCharacteristics;
	UINT64               SizeOfStackReserve;
	UINT64               SizeOfStackCommit;
	UINT64               SizeOfHeapReserve;
	UINT64               SizeOfHeapCommit;
	UINT32               LoaderFlags;
	UINT32               NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	UINT32 Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
	UINT8    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		UINT32   PhysicalAddress;
		UINT32   VirtualSize;
	} Misc;
	UINT32   VirtualAddress;
	UINT32   SizeOfRawData;
	UINT32   PointerToRawData;
	UINT32   PointerToRelocations;
	UINT32   PointerToLinenumbers;
	UINT16   NumberOfRelocations;
	UINT16   NumberOfLinenumbers;
	UINT32   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

//typedef struct _IMAGE_THUNK_DATA64 {
//	union {
//		UINT64 ForwarderString;
//		UINT64 Function;
//		UINT64 Ordinal;
//		UINT64 AddressOfData;
//	} u1;
//} IMAGE_THUNK_DATA64;


typedef struct _IMAGE_EXPORT_DIRECTORY {
	UINT32 Characteristics;
	UINT32 TimeDateStamp;
	UINT16 MajorVersion;
	UINT16 MinorVersion;
	UINT32 Name;
	UINT32 Base;
	UINT32 NumberOfFunctions;
	UINT32 NumberOfNames;
	UINT32 AddressOfFunctions;
	UINT32 AddressOfNames;
	UINT32 AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_BASE_RELOCATION {
	UINT32 VirtualAddress;
	UINT32 SizeOfBlock;
} IMAGE_BASE_RELOCATION;

//
// Waits for a timer event for N milliseconds.
// Requires current TPL to be TPL_APPLICATION.
//
EFI_STATUS
EFIAPI
RtlSleep(
	IN UINTN Milliseconds
	);

//
// Stalls CPU for N milliseconds.
//
EFI_STATUS
EFIAPI
RtlStall(
	IN UINTN Milliseconds
	);

// 
// Prints info about a loaded image
// 
VOID
EFIAPI
PrintLoadedImageInfo(
	IN CONST EFI_LOADED_IMAGE *ImageInfo
	);

//
// Similar to Print(), but for use during the kernel patching phase.
// Do not call this unless the message is specifically intended for (delayed) display output only.
// Instead use the PRINT_KERNEL_PATCH_MSG() macro so the boot debugger receives messages with no delay.
//
VOID
EFIAPI
AppendKernelPatchMessage(
	IN CONST CHAR16 *Format,
	...
	);

//
// Prints the contents of the kernel patch string buffer to the screen using OutputString() calls.
// This is a separate function because the buffer consists of zero or more null-terminated strings,
// which are printed sequentially to prevent issues with platforms that have small Print() buffer limits
//
VOID
EFIAPI
PrintKernelPatchInfo(
	VOID
	);

//
// Disables CET.
//
VOID
EFIAPI
AsmDisableCet(
	VOID
	);

//
// Enables CET.
//
VOID
EFIAPI
AsmEnableCet(
	VOID
	);

//
// Disables write protection if it is currently enabled.
// Returns the current CET and WP states for use when calling EnableWriteProtect().
//
VOID
EFIAPI
DisableWriteProtect(
	OUT BOOLEAN *WpEnabled,
	OUT BOOLEAN *CetEnabled
	);

//
// Enables write protection if it was previously enabled.
//
VOID
EFIAPI
EnableWriteProtect(
	IN BOOLEAN WpEnabled,
	IN BOOLEAN CetEnabled
	);

//
// Wrapper for CopyMem() that disables write protection prior to copying if needed.
//
VOID*
EFIAPI
CopyWpMem(
	OUT VOID *Destination,
	IN CONST VOID *Source,
	IN UINTN Length
	);

//
// Wrapper for SetMem() that disables write protection prior to copying if needed.
//
VOID*
EFIAPI
SetWpMem(
	OUT VOID *Destination,
	IN UINTN Length,
	IN UINT8 Value
	);

//
// Returns TRUE if 5-level paging is enabled.
//
BOOLEAN
EFIAPI
IsFiveLevelPagingEnabled(
	VOID
	);

//
// Case-insensitive string comparison.
//
INTN
EFIAPI
StrniCmp(
	IN CONST CHAR16 *FirstString,
	IN CONST CHAR16 *SecondString,
	IN UINTN Length
	);

//
// Case-insensitive string search.
//
CONST CHAR16*
EFIAPI
StriStr(
	IN CONST CHAR16 *String1,
	IN CONST CHAR16 *String2
	);

//
// Waits for a key to be pressed before continuing execution.
// Returns FALSE if ESC was pressed to abort, TRUE otherwise.
//
BOOLEAN
EFIAPI
WaitForKey(
	VOID
	);

//
// Sets the foreground colour while preserving the background colour and optionally clears the screen.
// Returns the original console mode attribute.
//
INT32
EFIAPI
SetConsoleTextColour(
	IN UINTN TextColour,
	IN BOOLEAN ClearScreen
	);

//
// Finds a byte pattern starting at the specified address
//
EFI_STATUS
EFIAPI
FindPattern(
	IN CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	);

VOID* UMap_FindPattern(
	CHAR8* base,
	UINTN size,
	CHAR8* pattern,
	CHAR8* mask
);

//
// Finds a byte pattern starting at the specified address (with lots of debug spew)
//
EFI_STATUS
EFIAPI
FindPatternVerbose(
	IN CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	);

//
// Zydis instruction decoder context.
//
typedef struct _ZYDIS_CONTEXT
{
	ZydisDecoder Decoder;
	ZydisDecodedInstruction Instruction;
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

	ZyanU64 InstructionAddress;
	UINTN Length;
	UINTN Offset;

#ifndef ZYDIS_DISABLE_FORMATTER
	ZydisFormatter Formatter;
	CHAR8 InstructionText[256];
#endif
} ZYDIS_CONTEXT, *PZYDIS_CONTEXT;

//
// Initializes a decoder context.
//
ZyanStatus
EFIAPI
ZydisInit(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT PZYDIS_CONTEXT Context
	);

//
// Finds the start of a function given an address within it.
// Returns NULL if AddressInFunction is NULL (this simplifies error checking logic in calling functions).
//
UINT8*
EFIAPI
BacktrackToFunctionStart(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST UINT8* AddressInFunction
	);


VOID* UMap_TrampolineHook(
	VOID* dest,
	VOID* src,
	UINT8 original[JMP_SIZE]);

VOID UMap_TrampolineUnHook(
	VOID* src,
	UINT8 original[JMP_SIZE]
);

KLDR_DATA_TABLE_ENTRY*
UMap_GetModuleEntry(
	LIST_ENTRY* list,
	CHAR16* name
);

VOID UMap_MemCopy(
	VOID* dest,
	VOID* src,
	UINTN size);

UINT64 UMap_GetExport(
	UINT8* base,
	CHAR8* export
);
