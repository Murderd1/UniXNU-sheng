/** @file
  Diagnostic protocol for the isolated, read-only sheng initrd FAT transport.

  Copyright (c) 2026, UniXNU contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef SHENG_KERNEL_DISK_DIAGNOSTIC_H
#define SHENG_KERNEL_DISK_DIAGNOSTIC_H

#include <Uefi.h>

#define SHENG_KERNEL_DISK_DIAGNOSTIC_PROTOCOL_GUID \
  { 0x3C260617, 0x3CA2, 0x4A31, { 0xA5, 0x20, 0x37, 0x07, 0x78, 0xDC, 0x1B, 0xCB } }

#define SHENG_KERNEL_DISK_DIAGNOSTIC_REVISION  1U
#define SHENG_KERNEL_DISK_FLAG_FDT_VALID      BIT0
#define SHENG_KERNEL_DISK_FLAG_INITRD_PRESENT BIT1
#define SHENG_KERNEL_DISK_FLAG_RANGE_RESERVED BIT2
#define SHENG_KERNEL_DISK_FLAG_PREFIX_MATCH   BIT3
#define SHENG_KERNEL_DISK_FLAG_BOOT_SHA_MATCH BIT4
#define SHENG_KERNEL_DISK_FLAG_FAT_GEOMETRY   BIT5
#define SHENG_KERNEL_DISK_FLAG_VOLUME_SHA_MATCH BIT6
#define SHENG_KERNEL_DISK_FLAG_PUBLISHED      BIT7

typedef enum {
  ShengKernelDiskInitializing,
  ShengKernelDiskNoEntryHob,
  ShengKernelDiskInvalidFdt,
  ShengKernelDiskNoInitrd,
  ShengKernelDiskInvalidInitrdRange,
  ShengKernelDiskUnreservedInitrd,
  ShengKernelDiskVolumeNotFound,
  ShengKernelDiskVolumeDigestMismatch,
  ShengKernelDiskVolumePublished,
  ShengKernelDiskOutOfResources,
  ShengKernelDiskProtocolError
} SHENG_KERNEL_DISK_STATE;

typedef struct {
  UINT32      Revision;
  UINT32      State;
  UINT32      Flags;
  UINT32      Reserved;
  EFI_STATUS  Status;
  EFI_STATUS  RangeStatus;
  UINT64      EntryArg0;
  UINT64      FdtBytes;
  UINT64      InitrdStart;
  UINT64      InitrdEnd;
  UINT64      FatOffset;
  UINT64      FatBytes;
  UINT64      ScannedBytes;
  UINT32      PrefixCandidates;
  UINT32      BootSectorCandidates;
  UINT8       Prefix[16];
  UINT8       ExpectedSha256[32];
  UINT8       VolumeSha256[32];
  EFI_HANDLE  VolumeHandle;
} SHENG_KERNEL_DISK_DIAGNOSTIC;

#endif
