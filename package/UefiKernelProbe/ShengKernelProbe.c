/** @file
  Display the firmware's saved initrd transport observation. No raw boot
  address is dereferenced here. Only the driver's digest-verified read-only
  volume can supply the full kernel and Data seed for an explicit Boot call.

  Copyright (c) 2026, UniXNU contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Guid/FileInfo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/UniXNULoader.h>

#include "../UefiKernelDisk/ShengKernelDiskDiagnostic.h"
#include "ShengFullTrialConfig.h"

#ifndef SHENG_KERNEL_PROBE_BUILD_ID
#define SHENG_KERNEL_PROBE_BUILD_ID "unversioned"
#endif

#ifndef SCAN_SUSPEND
#define SCAN_SUSPEND  0x0102
#endif

#define PROBE_PAGE_COUNT  5U
#define PROBE_FILE_COUNT  6U

STATIC EFI_GUID  mDiagnosticGuid = SHENG_KERNEL_DISK_DIAGNOSTIC_PROTOCOL_GUID;
STATIC SHENG_KERNEL_DISK_DIAGNOSTIC  mDiagnostic;
STATIC EFI_STATUS  mDiagnosticStatus;
STATIC EFI_STATUS  mVolumeStatus = EFI_NOT_READY;
STATIC EFI_STATUS  mLoaderStatus = EFI_NOT_READY;
STATIC EFI_STATUS  mLastBootStatus = EFI_NOT_READY;
STATIC EFI_STATUS  mWatchdogStatus;
STATIC UINT64      mCurrentEl;
STATIC UINTN       mReadOnlyVolumes;
STATIC UINTN       mPage;
STATIC BOOLEAN     mConfirming;
STATIC BOOLEAN     mConfirmBoot;
STATIC BOOLEAN     mBootAttempted;
STATIC BOOLEAN     mVerifiedVolume;
STATIC BOOLEAN     mArgumentsSafe;
STATIC EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *mFileSystem;
STATIC UNIXNU_LOADER_PROTOCOL           *mLoader;

typedef struct {
  CONST CHAR16  *Path;
  CONST CHAR16  *Label;
  EFI_STATUS    Status;
  UINT64        Bytes;
} PROBE_FILE;

STATIC PROBE_FILE  mFiles[PROBE_FILE_COUNT] = {
  { L"\\EFI\\UniXNU\\Payloads\\kernel.macho", L"kernel.macho", EFI_NOT_READY, 0 },
  { L"\\EFI\\UniXNU\\Payloads\\kernel.macho.adt", L"kernel.macho.adt", EFI_NOT_READY, 0 },
  { L"\\EFI\\UniXNU\\Payloads\\kernel.macho.trustcache", L"trustcache", EFI_NOT_READY, 0 },
  { L"\\EFI\\UniXNU\\Payloads\\kernel.macho.vroot", L"root policies", EFI_NOT_READY, 0 },
  { L"\\EFI\\UniXNU\\Payloads\\kernel.macho.gpuaddon", L"GPU addon", EFI_NOT_READY, 0 },
  { L"\\EFI\\UniXNU\\Payloads\\scratch-data.img", L"Data seed", EFI_NOT_READY, 0 }
};

STATIC
BOOLEAN
TokenIs (
  IN CONST CHAR16  *Token,
  IN UINTN         Length,
  IN CONST CHAR16  *Expected
  )
{
  return (BOOLEAN)((Length == StrLen (Expected)) && (StrnCmp (Token, Expected, Length) == 0));
}

STATIC
BOOLEAN
TokenNames (
  IN CONST CHAR16  *Token,
  IN UINTN         Length,
  IN CONST CHAR16  *Name
  )
{
  UINTN  NameLength;

  NameLength = StrLen (Name);
  return (BOOLEAN)((Length >= NameLength) && (StrnCmp (Token, Name, NameLength) == 0) &&
                   ((Length == NameLength) || (Token[NameLength] == L'=')));
}

STATIC
BOOLEAN
CheckArguments (
  VOID
  )
{
  CONST CHAR16  *Token;
  CONST CHAR16  *End;
  UINTN         Length;
  UINTN         DataCount;
  UINTN         LogCount;
  UINTN         SourceCount;
  UINTN         RootCount;

  Token = SHENG_FULL_TRIAL_ARGS;
  if (StrLen (Token) > 1000) {
    return FALSE;
  }
  DataCount = LogCount = SourceCount = RootCount = 0;
  while (*Token != L'\0') {
    if (*Token == L' ') {
      Token++;
      continue;
    }
    End = Token;
    while ((*End != L'\0') && (*End != L' ')) {
      // Generated arguments use printable ASCII and spaces. Refuse hidden
      // separators before applying the guarded-name checks below.
      if ((*End < 0x20) || (*End > 0x7E)) {
        return FALSE;
      }
      End++;
    }
    Length = (UINTN)(End - Token);
    if (TokenNames (Token, Length, L"data-reset") || TokenNames (Token, Length, L"autoreset")) {
      return FALSE;
    }
    if (TokenNames (Token, Length, L"data-persist")) {
      if (!TokenIs (Token, Length, L"data-persist=0")) { return FALSE; }
      DataCount++;
    }
    if (TokenNames (Token, Length, L"log")) {
      if (!TokenIs (Token, Length, L"log=0")) { return FALSE; }
      LogCount++;
    }
    if (TokenNames (Token, Length, L"native-source-storage")) {
      if (!TokenIs (Token, Length, L"native-source-storage=1")) { return FALSE; }
      SourceCount++;
    }
    if (TokenNames (Token, Length, L"native-ufs-root")) {
      if (!TokenIs (Token, Length, L"native-ufs-root=1")) { return FALSE; }
      RootCount++;
    }
    Token = End;
  }
  return (BOOLEAN)((DataCount == 1) && (LogCount == 1) && (SourceCount == 1) && (RootCount == 1));
}

STATIC
CONST CHAR16 *
StateName (
  IN UINT32  State
  )
{
  switch (State) {
    case ShengKernelDiskInitializing: return L"INITIALIZING";
    case ShengKernelDiskNoEntryHob: return L"NO ENTRY HOB";
    case ShengKernelDiskInvalidFdt: return L"INVALID FDT";
    case ShengKernelDiskNoInitrd: return L"NO INITRD";
    case ShengKernelDiskInvalidInitrdRange: return L"INVALID INITRD RANGE";
    case ShengKernelDiskUnreservedInitrd: return L"INITRD NOT RESERVED";
    case ShengKernelDiskVolumeNotFound: return L"VOLUME NOT FOUND";
    case ShengKernelDiskVolumeDigestMismatch: return L"VOLUME DIGEST MISMATCH";
    case ShengKernelDiskVolumePublished: return L"VOLUME PUBLISHED";
    case ShengKernelDiskOutOfResources: return L"OUT OF RESOURCES";
    case ShengKernelDiskProtocolError: return L"PROTOCOL ERROR";
    default: return L"UNKNOWN STATE";
  }
}

STATIC
CONST CHAR16 *
FlagName (
  IN UINT32  Flag
  )
{
  return (mDiagnostic.Flags & Flag) != 0 ? L"YES" : L"NO";
}

STATIC
EFI_STATUS
FileSize (
  IN EFI_FILE_PROTOCOL  *File,
  OUT UINT64            *Bytes
  )
{
  EFI_FILE_INFO  *Info;
  EFI_STATUS     Status;
  UINTN          Size;

  Info = NULL;
  Size = 0;
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &Size, NULL);
  if ((Status != EFI_BUFFER_TOO_SMALL) || (Size < SIZE_OF_EFI_FILE_INFO) || (Size > 4096)) {
    return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
  }

  Info = AllocatePool (Size);
  if (Info == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = File->GetInfo (File, &gEfiFileInfoGuid, &Size, Info);
  if (!EFI_ERROR (Status)) {
    if ((Size < SIZE_OF_EFI_FILE_INFO) || ((Info->Attribute & EFI_FILE_DIRECTORY) != 0)) {
      Status = EFI_COMPROMISED_DATA;
    } else {
      *Bytes = Info->FileSize;
    }
  }

  FreePool (Info);
  return Status;
}

STATIC
VOID
Snapshot (
  VOID
  )
{
  SHENG_KERNEL_DISK_DIAGNOSTIC  *Diagnostic;
  EFI_BLOCK_IO_PROTOCOL        *Block;
  EFI_HANDLE                   *Handles;
  EFI_FILE_PROTOCOL            *Root;
  EFI_FILE_PROTOCOL            *File;
  EFI_STATUS                   Status;
  UINTN                        Count;
  UINTN                        Index;

  // This reports the exception level of this EFI application only.
#if defined (MDE_CPU_AARCH64) && !defined (SHENG_KERNEL_PROBE_HOST_TEST)
  __asm__ __volatile__ ("mrs %0, CurrentEL" : "=r" (mCurrentEl));
#endif
  Diagnostic = NULL;
  mArgumentsSafe = CheckArguments ();
  mDiagnostic.Status = EFI_NOT_READY;
  mDiagnostic.RangeStatus = EFI_NOT_READY;
  mDiagnosticStatus = gBS->LocateProtocol (&mDiagnosticGuid, NULL, (VOID **)&Diagnostic);
  if (!EFI_ERROR (mDiagnosticStatus) && (Diagnostic != NULL)) {
    if (Diagnostic->Revision != SHENG_KERNEL_DISK_DIAGNOSTIC_REVISION) {
      mDiagnosticStatus = EFI_INCOMPATIBLE_VERSION;
    } else {
      CopyMem (&mDiagnostic, Diagnostic, sizeof (mDiagnostic));
    }
  } else if (!EFI_ERROR (mDiagnosticStatus)) {
    mDiagnosticStatus = EFI_COMPROMISED_DATA;
  }

  Handles = NULL;
  Count = 0;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &Count, &Handles);
  if (!EFI_ERROR (Status)) {
    for (Index = 0; Index < Count; ++Index) {
      Block = NULL;
      if (!EFI_ERROR (gBS->HandleProtocol (Handles[Index], &gEfiBlockIoProtocolGuid, (VOID **)&Block)) &&
          (Block != NULL) && (Block->Media != NULL) && Block->Media->ReadOnly)
      {
        mReadOnlyVolumes++;
      }
    }
    FreePool (Handles);
  }

  if (EFI_ERROR (mDiagnosticStatus) ||
      EFI_ERROR (mDiagnostic.Status) || EFI_ERROR (mDiagnostic.RangeStatus) ||
      (mDiagnostic.State != ShengKernelDiskVolumePublished) ||
      ((mDiagnostic.Flags & (SHENG_KERNEL_DISK_FLAG_PUBLISHED | SHENG_KERNEL_DISK_FLAG_VOLUME_SHA_MATCH)) !=
       (SHENG_KERNEL_DISK_FLAG_PUBLISHED | SHENG_KERNEL_DISK_FLAG_VOLUME_SHA_MATCH)) ||
      (mDiagnostic.VolumeHandle == NULL))
  {
    mVolumeStatus = EFI_NOT_FOUND;
    return;
  }

  Block = NULL;
  mVolumeStatus = gBS->HandleProtocol (mDiagnostic.VolumeHandle, &gEfiBlockIoProtocolGuid, (VOID **)&Block);
  if (EFI_ERROR (mVolumeStatus) || (Block == NULL) || (Block->Media == NULL) || !Block->Media->ReadOnly) {
    mVolumeStatus = EFI_WRITE_PROTECTED;
    return;
  }

  mVolumeStatus = gBS->HandleProtocol (mDiagnostic.VolumeHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&mFileSystem);
  if (EFI_ERROR (mVolumeStatus) || (mFileSystem == NULL)) {
    return;
  }

  Root = NULL;
  mVolumeStatus = mFileSystem->OpenVolume (mFileSystem, &Root);
  if (EFI_ERROR (mVolumeStatus) || (Root == NULL)) {
    return;
  }

  for (Index = 0; Index < PROBE_FILE_COUNT; ++Index) {
    File = NULL;
    mFiles[Index].Status = Root->Open (Root, &File, (CHAR16 *)mFiles[Index].Path, EFI_FILE_MODE_READ, 0);
    if (!EFI_ERROR (mFiles[Index].Status) && (File != NULL)) {
      mFiles[Index].Status = FileSize (File, &mFiles[Index].Bytes);
      File->Close (File);
    }
  }
  Root->Close (Root);
  mVerifiedVolume = TRUE;
  mLoaderStatus = gBS->LocateProtocol (&gUniXNULoaderProtocolGuid, NULL, (VOID **)&mLoader);
  if (!EFI_ERROR (mLoaderStatus) && ((mLoader == NULL) || (mLoader->Boot == NULL) ||
      ((mLoader->Revision != UNIXNU_LOADER_REVISION_1) && (mLoader->Revision != UNIXNU_LOADER_REVISION))))
  {
    mLoaderStatus = EFI_UNSUPPORTED;
  }
}

STATIC
BOOLEAN
CanBoot (
  VOID
  )
{
  UINTN  Index;

  if (!mVerifiedVolume || !mArgumentsSafe || EFI_ERROR (mLoaderStatus) || mBootAttempted ||
      (mFiles[PROBE_FILE_COUNT - 1].Bytes != SHENG_FULL_TRIAL_RAMDISK_BYTES) ||
      (SHENG_FULL_TRIAL_RAMDISK_BYTES == 0) || (SHENG_FULL_TRIAL_RAMDISK_BYTES > MAX_UINTN))
  {
    return FALSE;
  }
  for (Index = 0; Index < PROBE_FILE_COUNT; ++Index) {
    if (EFI_ERROR (mFiles[Index].Status) || (mFiles[Index].Bytes == 0)) {
      return FALSE;
    }
  }
  return TRUE;
}

STATIC
VOID
PrintDigest (
  IN CONST UINT8  *Digest
  )
{
  UINTN  Index;

  for (Index = 0; Index < 32; ++Index) {
    Print (L"%02x", (UINT32)Digest[Index]);
  }
  Print (L"\n");
}

STATIC
VOID
Draw (
  VOID
  )
{
  UINTN  Index;

  if (gST->ConOut != NULL) {
    gST->ConOut->SetAttribute (gST->ConOut, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
    gST->ConOut->ClearScreen (gST->ConOut);
  }
  Print (L"SHENG KERNEL TRANSPORT PROBE\nBuild: %a\n", SHENG_KERNEL_PROBE_BUILD_ID);
  Print (L"Page %u/%u  EFI app CurrentEL=%u (raw 0x%lx)\n",
         (UINT32)mPage + 1, PROBE_PAGE_COUNT, (UINT32)(mCurrentEl >> 2), mCurrentEl);
  Print (L"This screen records UEFI transport; it does not prove XNU execution.\n\n");

  if (mConfirming) {
    Print (L"Confirm full XNU handoff\n\n");
    Print (L"The full kernel and sidecars come from the verified read-only volume.\n");
    Print (L"Data persistence=0; UFS log/export=0.\n\n");
    Print (L"%s Cancel\n%s BOOT FULL XNU ONCE\n\n",
           mConfirmBoot ? L" " : L">", mConfirmBoot ? L">" : L" ");
    Print (L"Volume up/down selects; Power/Enter confirms. Esc cancels.\n");
    return;
  }

  switch (mPage) {
    case 0:
      Print (L"Protocol: %r  Driver state: %s\n", mDiagnosticStatus, StateName (mDiagnostic.State));
      Print (L"Driver status: %r  Range status: %r\n", mDiagnostic.Status, mDiagnostic.RangeStatus);
      Print (L"Saved raw entry x0: 0x%016lx  FDT bytes: 0x%lx\n", mDiagnostic.EntryArg0, mDiagnostic.FdtBytes);
      Print (L"Initrd start: 0x%016lx\nInitrd end:   0x%016lx\n", mDiagnostic.InitrdStart, mDiagnostic.InitrdEnd);
      Print (L"FDT valid=%s  Initrd present=%s  Reserved=%s\n",
             FlagName (SHENG_KERNEL_DISK_FLAG_FDT_VALID), FlagName (SHENG_KERNEL_DISK_FLAG_INITRD_PRESENT),
             FlagName (SHENG_KERNEL_DISK_FLAG_RANGE_RESERVED));
      Print (L"FAT offset: 0x%lx  FAT bytes: 0x%lx\nScanned bytes: 0x%lx\n",
             mDiagnostic.FatOffset, mDiagnostic.FatBytes, mDiagnostic.ScannedBytes);
      Print (L"Prefix candidates=%u  Boot-sector candidates=%u\n", mDiagnostic.PrefixCandidates, mDiagnostic.BootSectorCandidates);
      break;
    case 1:
      Print (L"Raw initrd first 16 bytes (driver snapshot):\n");
      for (Index = 0; Index < sizeof (mDiagnostic.Prefix); ++Index) {
        Print (L"%02x ", (UINT32)mDiagnostic.Prefix[Index]);
      }
      Print (L"\nPrefix match=%s  Boot SHA match=%s  FAT geometry=%s\n",
             FlagName (SHENG_KERNEL_DISK_FLAG_PREFIX_MATCH), FlagName (SHENG_KERNEL_DISK_FLAG_BOOT_SHA_MATCH),
             FlagName (SHENG_KERNEL_DISK_FLAG_FAT_GEOMETRY));
      Print (L"Expected volume SHA-256:\n"); PrintDigest (mDiagnostic.ExpectedSha256);
      Print (L"Observed volume SHA-256:\n"); PrintDigest (mDiagnostic.VolumeSha256);
      Print (L"Volume SHA match=%s  Published=%s\n", FlagName (SHENG_KERNEL_DISK_FLAG_VOLUME_SHA_MATCH),
             FlagName (SHENG_KERNEL_DISK_FLAG_PUBLISHED));
      break;
    case 2:
      Print (L"Read-only filesystem handles: %u\n", (UINT32)mReadOnlyVolumes);
      Print (L"Verified block/filesystem handle: %p\nStatus: %r\n\n", mDiagnostic.VolumeHandle, mVolumeStatus);
      for (Index = 0; Index < PROBE_FILE_COUNT; ++Index) {
        Print (L"%-20s %r  %lu bytes\n", mFiles[Index].Label, mFiles[Index].Status, mFiles[Index].Bytes);
      }
      Print (L"\nExpected Data seed: %lu bytes\n", (UINT64)SHENG_FULL_TRIAL_RAMDISK_BYTES);
      break;
    case 3:
      Print (L"> Boot full XNU once\n\n");
      Print (L"Verified read-only volume: %s\nLoader protocol: %r\nBoot arguments checked: %s\nBoot available: %s\n",
             mVerifiedVolume ? L"YES" : L"NO", mLoaderStatus, mArgumentsSafe ? L"YES" : L"NO", CanBoot () ? L"YES" : L"NO");
      Print (L"Data persistence=0  UFS log/export=0\n");
      if (mBootAttempted) {
        Print (L"\nHANDOFF RETURNED: %r\nNo retry or automatic action will run.\n", mLastBootStatus);
      } else {
        Print (L"\nPower/Enter opens a separate confirmation.\n");
      }
      break;
    default:
      Print (L"Recovery instructions\n\n");
      Print (L"Hold Power + Volume Down to return to Fastboot.\n");
      Print (L"This diagnostic stays visible until a hardware restart.\n");
      break;
  }
  Print (L"\nWatchdog disable: %r\n", mWatchdogStatus);
  Print (L"Volume up/down: change page. Power/Enter: select. Esc: cancel confirmation.\n");
}

STATIC
EFI_STATUS
BootFullKernel (
  VOID
  )
{
  UNIXNU_LOADER_BOOT_REQUEST  Request;
  EFI_FILE_PROTOCOL          *Root;
  EFI_FILE_PROTOCOL          *File;
  EFI_STATUS                 Status;
  VOID                       *Seed;
  UINT64                     Bytes;
  UINTN                      ReadBytes;
  UINTN                      Total;

  if (!CanBoot ()) {
    return EFI_NOT_READY;
  }
  mBootAttempted = TRUE;
  Print (L"\nReading exact-size Data seed from verified read-only volume...\n");
  Root = NULL;
  File = NULL;
  Seed = NULL;
  Status = mFileSystem->OpenVolume (mFileSystem, &Root);
  if (EFI_ERROR (Status) || (Root == NULL)) {
    return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
  }
  Status = Root->Open (Root, &File, (CHAR16 *)mFiles[PROBE_FILE_COUNT - 1].Path, EFI_FILE_MODE_READ, 0);
  Root->Close (Root);
  if (EFI_ERROR (Status) || (File == NULL)) {
    return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
  }
  Bytes = 0;
  Status = FileSize (File, &Bytes);
  if (EFI_ERROR (Status) || (Bytes != SHENG_FULL_TRIAL_RAMDISK_BYTES)) {
    File->Close (File);
    return EFI_ERROR (Status) ? Status : EFI_BAD_BUFFER_SIZE;
  }
  Seed = AllocatePool ((UINTN)Bytes);
  if (Seed == NULL) {
    File->Close (File);
    return EFI_OUT_OF_RESOURCES;
  }
  Total = 0;
  while (Total < (UINTN)Bytes) {
    ReadBytes = (UINTN)Bytes - Total;
    if (ReadBytes > 1024 * 1024) {
      ReadBytes = 1024 * 1024;
    }
    Status = File->Read (File, &ReadBytes, (UINT8 *)Seed + Total);
    if (EFI_ERROR (Status) || (ReadBytes == 0) || (ReadBytes > (UINTN)Bytes - Total)) {
      File->Close (File);
      FreePool (Seed);
      return EFI_ERROR (Status) ? Status : EFI_END_OF_FILE;
    }
    Total += ReadBytes;
  }
  File->Close (File);
  ZeroMem (&Request, sizeof (Request));
  Request.Volume = mDiagnostic.VolumeHandle;
  Request.KernelPath = mFiles[0].Path;
  Request.BootArgs = SHENG_FULL_TRIAL_ARGS;
  Request.Ramdisk = Seed;
  Request.RamdiskSize = (UINTN)Bytes;
  Print (L"Calling DarwinBoot with the verified volume; no kernel checkpoint claimed.\n");
  Status = mLoader->Boot (mLoader, &Request);
  FreePool (Seed);
  return Status;
}

EFI_STATUS
EFIAPI
ShengKernelProbeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_INPUT_KEY  Key;
  EFI_STATUS     Status;
  UINTN          Index;
  BOOLEAN        Select;

  (VOID)ImageHandle;
  (VOID)SystemTable;
  mWatchdogStatus = gBS->SetWatchdogTimer (0, 0, 0, NULL);
  Snapshot ();
  // Drop the key that launched this payload before any selectable action.
  if (gST->ConIn != NULL) {
    while (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key))) {
    }
  }
  Draw ();
  for (;;) {
    if ((gST->ConIn == NULL) || (gST->ConIn->WaitForKey == NULL)) {
      // Keep the report visible if input is missing; do not enter BDS fallback.
      gBS->Stall (1000000);
      continue;
    }
    Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &Index);
    if (EFI_ERROR (Status)) {
      gBS->Stall (100000);
      continue;
    }
    Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    if (EFI_ERROR (Status)) {
      continue;
    }
    Select = (BOOLEAN)((Key.UnicodeChar == CHAR_CARRIAGE_RETURN) ||
                       (Key.UnicodeChar == CHAR_LINEFEED) || (Key.UnicodeChar == L' ') ||
                       (Key.ScanCode == SCAN_RIGHT) || (Key.ScanCode == SCAN_SUSPEND));
    if (Key.ScanCode == SCAN_ESC) {
      if (mConfirming) {
        mConfirming = FALSE;
      }
    } else if ((Key.ScanCode == SCAN_UP) || (Key.ScanCode == SCAN_DOWN) ||
               (Key.UnicodeChar == L'k') || (Key.UnicodeChar == L'j'))
    {
      if (mConfirming) {
        mConfirmBoot = (BOOLEAN)!mConfirmBoot;
      } else if ((Key.ScanCode == SCAN_UP) || (Key.UnicodeChar == L'k')) {
        mPage = (mPage + PROBE_PAGE_COUNT - 1) % PROBE_PAGE_COUNT;
      } else {
        mPage = (mPage + 1) % PROBE_PAGE_COUNT;
      }
    } else if (Select) {
      if (mConfirming) {
        mConfirming = FALSE;
        if (mConfirmBoot) {
          mLastBootStatus = BootFullKernel ();
          mPage = 3;
        }
      } else if ((mPage == 3) && CanBoot ()) {
        mConfirming = TRUE;
        mConfirmBoot = FALSE;
      }
    }
    Draw ();
  }
}
