/** @file
  Publish the stage 2 FAT image embedded in a firmware RAW section.

  The image and protocol storage remain allocated while boot services run.
  DiskIoDxe and Fat provide file access; this driver exposes only read-only
  512-byte Block I/O and never accesses the tablet's persistent storage.

  Copyright (c) 2026, UniXNU contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>

#define MENU_DISK_BLOCK_SIZE  512U

// FDF: FILE FREEFORM = 79D77DA6-3053-4705-9B3C-18750AE7C3F1 {
//        SECTION RAW = Stage2Menu/menu-fat.img
//      }
STATIC CONST EFI_GUID  mMenuDiskPayloadGuid = {
  0x79D77DA6, 0x3053, 0x4705, { 0x9B, 0x3C, 0x18, 0x75, 0x0A, 0xE7, 0xC3, 0xF1 }
};

STATIC CONST EFI_GUID  mMenuDiskDevicePathGuid = {
  0xC165D00A, 0x8453, 0x4443, { 0x92, 0xAC, 0x34, 0x4E, 0x96, 0x27, 0x68, 0x42 }
};

#pragma pack(1)
typedef struct {
  VENDOR_DEVICE_PATH          Vendor;
  EFI_DEVICE_PATH_PROTOCOL    End;
} MENU_DISK_DEVICE_PATH;
#pragma pack()

typedef struct {
  EFI_HANDLE               Handle;
  VOID                     *Image;
  UINTN                    ImageSize;
  EFI_BLOCK_IO_MEDIA       Media;
  EFI_BLOCK_IO_PROTOCOL    BlockIo;
  MENU_DISK_DEVICE_PATH    DevicePath;
} MENU_DISK;

STATIC MENU_DISK  *mMenuDisk;

STATIC
BOOLEAN
IsMenuDisk (
  IN EFI_BLOCK_IO_PROTOCOL  *This
  )
{
  return (mMenuDisk != NULL) && (This == &mMenuDisk->BlockIo);
}

STATIC
EFI_STATUS
CheckTransfer (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  IN CONST VOID             *Buffer
  )
{
  UINTN  Blocks;

  if (!IsMenuDisk (This)) {
    return EFI_INVALID_PARAMETER;
  }

  if (MediaId != mMenuDisk->Media.MediaId) {
    return EFI_MEDIA_CHANGED;
  }

  if (!mMenuDisk->Media.MediaPresent) {
    return EFI_NO_MEDIA;
  }

  // A zero-byte request is a successful no-op and need not have a buffer.
  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }

  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((BufferSize % MENU_DISK_BLOCK_SIZE) != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Blocks = BufferSize / MENU_DISK_BLOCK_SIZE;
  // Subtraction avoids overflow in Lba + Blocks, including MAX_UINT64 LBA.
  if ((Lba > mMenuDisk->Media.LastBlock) ||
      ((Blocks - 1) > (mMenuDisk->Media.LastBlock - Lba)))
  {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MenuDiskReset (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN BOOLEAN                ExtendedVerification
  )
{
  (VOID)ExtendedVerification;
  return IsMenuDisk (This) ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

STATIC
EFI_STATUS
EFIAPI
MenuDiskRead (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  OUT VOID                  *Buffer
  )
{
  EFI_STATUS  Status;
  UINTN       Offset;

  Status = CheckTransfer (This, MediaId, Lba, BufferSize, Buffer);
  if (EFI_ERROR (Status) || (BufferSize == 0)) {
    return Status;
  }

  // The bounded LBA is at most ImageSize / BlockSize - 1, so this fits UINTN.
  Offset = (UINTN)Lba * MENU_DISK_BLOCK_SIZE;
  CopyMem (Buffer, (CONST UINT8 *)mMenuDisk->Image + Offset, BufferSize);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MenuDiskWrite (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  IN VOID                   *Buffer
  )
{
  EFI_STATUS  Status;

  Status = CheckTransfer (This, MediaId, Lba, BufferSize, Buffer);
  if (EFI_ERROR (Status) || (BufferSize == 0)) {
    return Status;
  }

  return EFI_WRITE_PROTECTED;
}

STATIC
EFI_STATUS
EFIAPI
MenuDiskFlush (
  IN EFI_BLOCK_IO_PROTOCOL  *This
  )
{
  return IsMenuDisk (This) ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

EFI_STATUS
EFIAPI
ShengMenuDiskDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  MENU_DISK   *Disk;

  (VOID)ImageHandle;
  (VOID)SystemTable;

  if (mMenuDisk != NULL) {
    return EFI_ALREADY_STARTED;
  }

  Disk = AllocateZeroPool (sizeof (*Disk));
  if (Disk == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // GetSectionFromAnyFv returns a pool allocation owned by this driver.
  Status = GetSectionFromAnyFv (
             &mMenuDiskPayloadGuid,
             EFI_SECTION_RAW,
             0,
             &Disk->Image,
             &Disk->ImageSize
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SHENGMENUDISK: RAW payload %g unavailable: %r\n", &mMenuDiskPayloadGuid, Status));
    goto Fail;
  }

  if ((Disk->Image == NULL) || (Disk->ImageSize < MENU_DISK_BLOCK_SIZE) ||
      ((Disk->ImageSize % MENU_DISK_BLOCK_SIZE) != 0))
  {
    Status = EFI_COMPROMISED_DATA;
    DEBUG ((DEBUG_ERROR, "SHENGMENUDISK: RAW payload %g has invalid size %Lu\n", &mMenuDiskPayloadGuid, (UINT64)Disk->ImageSize));
    goto Fail;
  }

  Disk->Media.MediaId                          = 1;
  Disk->Media.RemovableMedia                   = FALSE;
  Disk->Media.MediaPresent                     = TRUE;
  Disk->Media.LogicalPartition                 = FALSE;
  Disk->Media.ReadOnly                         = TRUE;
  Disk->Media.WriteCaching                     = FALSE;
  Disk->Media.BlockSize                        = MENU_DISK_BLOCK_SIZE;
  Disk->Media.IoAlign                          = 1;
  Disk->Media.LastBlock                        = Disk->ImageSize / MENU_DISK_BLOCK_SIZE - 1;
  Disk->Media.LowestAlignedLba                 = 0;
  Disk->Media.LogicalBlocksPerPhysicalBlock    = 1;
  Disk->Media.OptimalTransferLengthGranularity = 1;

  Disk->BlockIo.Revision    = EFI_BLOCK_IO_PROTOCOL_REVISION3;
  Disk->BlockIo.Media       = &Disk->Media;
  Disk->BlockIo.Reset       = MenuDiskReset;
  Disk->BlockIo.ReadBlocks  = MenuDiskRead;
  Disk->BlockIo.WriteBlocks = MenuDiskWrite;
  Disk->BlockIo.FlushBlocks = MenuDiskFlush;

  Disk->DevicePath.Vendor.Header.Type      = HARDWARE_DEVICE_PATH;
  Disk->DevicePath.Vendor.Header.SubType   = HW_VENDOR_DP;
  Disk->DevicePath.Vendor.Header.Length[0] = (UINT8)sizeof (VENDOR_DEVICE_PATH);
  Disk->DevicePath.Vendor.Header.Length[1] = (UINT8)(sizeof (VENDOR_DEVICE_PATH) >> 8);
  CopyMem (&Disk->DevicePath.Vendor.Guid, &mMenuDiskDevicePathGuid, sizeof (EFI_GUID));
  Disk->DevicePath.End.Type      = END_DEVICE_PATH_TYPE;
  Disk->DevicePath.End.SubType   = END_ENTIRE_DEVICE_PATH_SUBTYPE;
  Disk->DevicePath.End.Length[0] = (UINT8)sizeof (EFI_DEVICE_PATH_PROTOCOL);
  Disk->DevicePath.End.Length[1] = 0;

  // Protocol notification can run during installation, so callbacks must
  // already be able to identify their resident backing allocation.
  mMenuDisk = Disk;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Disk->Handle,
                  &gEfiDevicePathProtocolGuid,
                  &Disk->DevicePath,
                  &gEfiBlockIoProtocolGuid,
                  &Disk->BlockIo,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    mMenuDisk = NULL;
    DEBUG ((DEBUG_ERROR, "SHENGMENUDISK: protocol installation failed: %r\n", Status));
    goto Fail;
  }

  DEBUG ((DEBUG_WARN, "SHENGMENUDISK: published bytes=%Lu payload=%g device=%g\n", (UINT64)Disk->ImageSize, &mMenuDiskPayloadGuid, &mMenuDiskDevicePathGuid));
  return EFI_SUCCESS;

Fail:
  if (Disk->Image != NULL) {
    FreePool (Disk->Image);
  }

  FreePool (Disk);
  return Status;
}
