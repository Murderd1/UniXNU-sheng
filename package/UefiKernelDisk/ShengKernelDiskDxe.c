/** @file
  Publish only the SHA-256 identified FAT slice of a reserved ABL initrd.

  The SEC overlay reserves FDT/initrd pages before DXE allocations. This
  driver refuses an initrd that is not entirely EfiReservedMemoryType. Its
  diagnostic protocol is installed even when the handoff is missing.

  Copyright (c) 2026, UniXNU contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include "ShengKernelDiskDiagnostic.h"
#include "KernelDiskExpected.h"

#define BLOCK_BYTES       512U
#define MAX_INITRD_BYTES  (512ULL * 1024 * 1024)
#define MAX_FDT_BYTES     (16U * 1024 * 1024)
#define MAX_PREFIX_HITS   64U
#define MAX_VOLUME_HASHES 4U

STATIC CONST EFI_GUID mEntryArgGuid = {
  0xDAEE82E6, 0x8090, 0x4E72, { 0xBF, 0xB9, 0x78, 0xC1, 0x3C, 0xD4, 0xE3, 0x59 }
};
STATIC EFI_GUID mDiagnosticGuid = SHENG_KERNEL_DISK_DIAGNOSTIC_PROTOCOL_GUID;
STATIC CONST UINT8 mExpectedSha[32] = SHENG_KERNEL_DISK_EXPECTED_SHA256;
STATIC CONST UINT8 mExpectedBootSha[32] = SHENG_KERNEL_DISK_BOOT_SECTOR_SHA256;
STATIC CONST UINT8 mExpectedPrefix[16] = SHENG_KERNEL_DISK_BOOT_PREFIX;
STATIC SHENG_KERNEL_DISK_DIAGNOSTIC mDiagnostic;
STATIC EFI_HANDLE mDiagnosticHandle;

// SHA-256 is local because ENABLE_SECUREBOOT=0 maps BaseCryptLib to its null
// implementation. No secure-boot key configuration or crypto service is used.
typedef struct {
  UINT32 H[8];
  UINT64 Bytes;
  UINT8 Block[64];
  UINTN Used;
} SHA256_CONTEXT;

STATIC CONST UINT32 mShaK[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

STATIC UINT32 Ror (UINT32 X, UINTN N) { return (X >> N) | (X << (32 - N)); }

STATIC VOID ShaBlock (SHA256_CONTEXT *C, CONST UINT8 *P)
{
  UINT32 W[64], A, B, D, E, F, G, H, J, T1, T2, S0, S1;
  UINTN I;
  for (I = 0; I < 16; I++) {
    W[I] = ((UINT32)P[I*4] << 24) | ((UINT32)P[I*4+1] << 16) |
           ((UINT32)P[I*4+2] << 8) | P[I*4+3];
  }
  for (I = 16; I < 64; I++) {
    S0 = Ror (W[I-15],7) ^ Ror (W[I-15],18) ^ (W[I-15] >> 3);
    S1 = Ror (W[I-2],17) ^ Ror (W[I-2],19) ^ (W[I-2] >> 10);
    W[I] = W[I-16] + S0 + W[I-7] + S1;
  }
  A=C->H[0]; B=C->H[1]; D=C->H[2]; E=C->H[3];
  F=C->H[4]; G=C->H[5]; H=C->H[6]; J=C->H[7];
  for (I = 0; I < 64; I++) {
    S1 = Ror(F,6) ^ Ror(F,11) ^ Ror(F,25);
    T1 = J + S1 + ((F & G) ^ (~F & H)) + mShaK[I] + W[I];
    S0 = Ror(A,2) ^ Ror(A,13) ^ Ror(A,22);
    T2 = S0 + ((A & B) ^ (A & D) ^ (B & D));
    J=H; H=G; G=F; F=E+T1; E=D; D=B; B=A; A=T1+T2;
  }
  C->H[0]+=A; C->H[1]+=B; C->H[2]+=D; C->H[3]+=E;
  C->H[4]+=F; C->H[5]+=G; C->H[6]+=H; C->H[7]+=J;
}

STATIC VOID Hash256 (CONST UINT8 *Data, UINTN Bytes, UINT8 Digest[32])
{
  SHA256_CONTEXT C = {
    {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19},0,{0},0
  };
  UINTN N, I;
  UINT64 Bits = (UINT64)Bytes * 8;
  while (Bytes != 0) {
    N = MIN (Bytes, sizeof (C.Block) - C.Used);
    CopyMem (C.Block + C.Used, Data, N);
    C.Used += N; Data += N; Bytes -= N;
    if (C.Used == sizeof (C.Block)) { ShaBlock (&C, C.Block); C.Used=0; }
  }
  C.Block[C.Used++] = 0x80;
  if (C.Used > 56) {
    ZeroMem (C.Block + C.Used, 64 - C.Used); ShaBlock (&C,C.Block); C.Used=0;
  }
  ZeroMem (C.Block + C.Used, 56 - C.Used);
  for (I=0; I<8; I++) { C.Block[63-I]=(UINT8)(Bits >> (I*8)); }
  ShaBlock (&C,C.Block);
  for (I=0; I<8; I++) {
    Digest[I*4]=(UINT8)(C.H[I]>>24); Digest[I*4+1]=(UINT8)(C.H[I]>>16);
    Digest[I*4+2]=(UINT8)(C.H[I]>>8); Digest[I*4+3]=(UINT8)C.H[I];
  }
}

// The EFI map supplies bounds before any external pointer is dereferenced.
// MMIO/unusable/unaccepted memory is never treated as an FDT or initrd.
STATIC BOOLEAN ReadableType (UINT32 Type, BOOLEAN ReservedOnly)
{
  if (ReservedOnly) { return Type == EfiReservedMemoryType; }
  return Type == EfiReservedMemoryType || Type == EfiLoaderCode ||
         Type == EfiLoaderData || Type == EfiBootServicesCode ||
         Type == EfiBootServicesData || Type == EfiRuntimeServicesCode ||
         Type == EfiRuntimeServicesData || Type == EfiConventionalMemory ||
         Type == EfiACPIReclaimMemory || Type == EfiACPIMemoryNVS;
}

STATIC EFI_STATUS CheckMemory (UINT64 Base, UINT64 Bytes, BOOLEAN ReservedOnly)
{
  EFI_MEMORY_DESCRIPTOR *Map = NULL, *D;
  EFI_STATUS Status;
  UINTN Size=0, Capacity=0, Key, Stride=0, I, Attempt;
  UINT32 Version;
  UINT64 Cursor, End, DEnd;
  BOOLEAN Found;
  if (Bytes == 0 || Base > MAX_UINT64 - Bytes || Base > MAX_UINTN ||
      Bytes > MAX_UINTN - (UINTN)Base) { return EFI_INVALID_PARAMETER; }
  Status = gBS->GetMemoryMap (&Size, Map, &Key, &Stride, &Version);
  if (Status != EFI_BUFFER_TOO_SMALL || Stride < sizeof (*Map)) { return EFI_DEVICE_ERROR; }
  for (Attempt=0; Attempt<4; Attempt++) {
    if (Size > MAX_UINTN - 16*Stride) { return EFI_OUT_OF_RESOURCES; }
    Capacity=Size+16*Stride;
    Map=AllocatePool (Capacity);
    if (Map == NULL) { return EFI_OUT_OF_RESOURCES; }
    Size=Capacity;
    Status=gBS->GetMemoryMap (&Size,Map,&Key,&Stride,&Version);
    if (Status != EFI_BUFFER_TOO_SMALL) { break; }
    FreePool (Map); Map=NULL;
  }
  if (EFI_ERROR (Status)) { if (Map != NULL) { FreePool (Map); } return Status; }
  if (Stride < sizeof (*Map) || Size % Stride != 0) { FreePool(Map); return EFI_COMPROMISED_DATA; }
  Cursor=Base; End=Base+Bytes; Status=EFI_SUCCESS;
  while (Cursor < End) {
    Found=FALSE;
    for (I=0; I<Size/Stride; I++) {
      D=(EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map+I*Stride);
      if (D->NumberOfPages > (MAX_UINT64-D->PhysicalStart)/EFI_PAGE_SIZE) { continue; }
      DEnd=D->PhysicalStart+D->NumberOfPages*EFI_PAGE_SIZE;
      if (Cursor >= D->PhysicalStart && Cursor < DEnd) {
        if (!ReadableType (D->Type, ReservedOnly) || (D->Attribute & EFI_MEMORY_RP)!=0) { Status=EFI_ACCESS_DENIED; }
        else { Cursor=MIN (End,DEnd); Found=TRUE; }
        break;
      }
    }
    if (EFI_ERROR(Status) || !Found) { if (!EFI_ERROR(Status)) { Status=EFI_NOT_FOUND; } break; }
  }
  FreePool (Map);
  return Status;
}

STATIC BOOLEAN FatGeometry (CONST UINT8 *B, UINT64 Bytes)
{
  UINT32 Bps, Spc, Reserved, Fats, Root, Total, Fat, RootSectors;
  UINT64 Data, Clusters;
  if (Bytes < BLOCK_BYTES || Bytes % BLOCK_BYTES != 0 || B[510]!=0x55 || B[511]!=0xAA) { return FALSE; }
  Bps=ReadUnaligned16((CONST UINT16 *)(B+11)); Spc=B[13];
  Reserved=ReadUnaligned16((CONST UINT16 *)(B+14)); Fats=B[16];
  Root=ReadUnaligned16((CONST UINT16 *)(B+17));
  Total=ReadUnaligned16((CONST UINT16 *)(B+19));
  if (Total==0) { Total=ReadUnaligned32((CONST UINT32 *)(B+32)); }
  Fat=ReadUnaligned16((CONST UINT16 *)(B+22));
  if (Fat==0) { Fat=ReadUnaligned32((CONST UINT32 *)(B+36)); }
  if (Bps!=BLOCK_BYTES || Spc==0 || Spc>128 || (Spc & (Spc-1))!=0 ||
      Reserved==0 || Fats==0 || Fats>2 || Fat==0 || (UINT64)Total*Bps!=Bytes ||
      ReadUnaligned32((CONST UINT32 *)(B+28))!=0) { return FALSE; }
  RootSectors=(Root*32+Bps-1)/Bps;
  Data=(UINT64)Reserved+(UINT64)Fats*Fat+RootSectors;
  if (Data>=Total) { return FALSE; }
  Clusters=(Total-Data)/Spc;
  if (Root!=0) { return Clusters>=4085 && Clusters<65525 && (UINT64)Fat*Bps>=(Clusters+2)*2; }
  return Clusters>=65525 && Clusters<0x0FFFFFF5 && (UINT64)Fat*Bps>=(Clusters+2)*4;
}

STATIC EFI_STATUS FindFat (CONST UINT8 *Raw, UINTN RawBytes, UINTN *FoundOffset)
{
  UINTN Offset, Limit;
  UINT32 Hashes=0;
  UINT8 Digest[32];
  BOOLEAN Mismatch=FALSE;
  CONST UINT64 Expected=SHENG_KERNEL_DISK_EXPECTED_BYTES;
  if (Expected < BLOCK_BYTES || Expected > MAX_INITRD_BYTES || Expected%BLOCK_BYTES!=0 || Expected>RawBytes) {
    return EFI_BAD_BUFFER_SIZE;
  }
  Limit=RawBytes-(UINTN)Expected;
  for (Offset=0; Offset<=Limit; Offset++) {
    mDiagnostic.ScannedBytes=(UINT64)Offset+1;
    if (Raw[Offset]!=mExpectedPrefix[0] || CompareMem(Raw+Offset,mExpectedPrefix,sizeof(mExpectedPrefix))!=0) { continue; }
    mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_PREFIX_MATCH;
    if (++mDiagnostic.PrefixCandidates>MAX_PREFIX_HITS) { return EFI_COMPROMISED_DATA; }
    Hash256(Raw+Offset,BLOCK_BYTES,Digest);
    if (CompareMem(Digest,mExpectedBootSha,sizeof(Digest))!=0) { continue; }
    mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_BOOT_SHA_MATCH;
    mDiagnostic.BootSectorCandidates++;
    if (!FatGeometry(Raw+Offset,Expected)) { continue; }
    mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_FAT_GEOMETRY;
    mDiagnostic.FatOffset=Offset;
    if (++Hashes>MAX_VOLUME_HASHES) { return EFI_COMPROMISED_DATA; }
    Hash256(Raw+Offset,(UINTN)Expected,mDiagnostic.VolumeSha256);
    if (CompareMem(mDiagnostic.VolumeSha256,mExpectedSha,sizeof(mExpectedSha))!=0) { Mismatch=TRUE; continue; }
    mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_VOLUME_SHA_MATCH;
    *FoundOffset=Offset;
    return EFI_SUCCESS;
  }
  return Mismatch ? EFI_CRC_ERROR : EFI_NOT_FOUND;
}

#pragma pack(1)
typedef struct { VENDOR_DEVICE_PATH Vendor; EFI_DEVICE_PATH_PROTOCOL End; } DISK_PATH;
#pragma pack()
typedef struct {
  EFI_HANDLE Handle;
  CONST UINT8 *Image;
  UINTN ImageSize;
  EFI_BLOCK_IO_MEDIA Media;
  EFI_BLOCK_IO_PROTOCOL BlockIo;
  DISK_PATH Path;
} KERNEL_DISK;
STATIC KERNEL_DISK mDisk;

STATIC EFI_STATUS CheckTransfer (EFI_BLOCK_IO_PROTOCOL *This, UINT32 Id, EFI_LBA Lba, UINTN Bytes, CONST VOID *Buffer)
{
  UINTN Blocks;
  if (This!=&mDisk.BlockIo) { return EFI_INVALID_PARAMETER; }
  if (Id!=mDisk.Media.MediaId) { return EFI_MEDIA_CHANGED; }
  if (!mDisk.Media.MediaPresent) { return EFI_NO_MEDIA; }
  if (Bytes==0) { return EFI_SUCCESS; }
  if (Buffer==NULL) { return EFI_INVALID_PARAMETER; }
  if (Bytes%BLOCK_BYTES!=0) { return EFI_BAD_BUFFER_SIZE; }
  Blocks=Bytes/BLOCK_BYTES;
  if (Lba>mDisk.Media.LastBlock || Blocks-1>mDisk.Media.LastBlock-Lba) { return EFI_INVALID_PARAMETER; }
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI DiskReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended)
{ (VOID)Extended; return This==&mDisk.BlockIo ? EFI_SUCCESS : EFI_INVALID_PARAMETER; }
STATIC EFI_STATUS EFIAPI DiskRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 Id, EFI_LBA Lba, UINTN Bytes, VOID *Buffer)
{
  EFI_STATUS Status=CheckTransfer(This,Id,Lba,Bytes,Buffer);
  if (!EFI_ERROR(Status) && Bytes!=0) { CopyMem(Buffer,mDisk.Image+(UINTN)Lba*BLOCK_BYTES,Bytes); }
  return Status;
}
STATIC EFI_STATUS EFIAPI DiskWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 Id, EFI_LBA Lba, UINTN Bytes, VOID *Buffer)
{
  EFI_STATUS Status=CheckTransfer(This,Id,Lba,Bytes,Buffer);
  return EFI_ERROR(Status) || Bytes==0 ? Status : EFI_WRITE_PROTECTED;
}
STATIC EFI_STATUS EFIAPI DiskFlush (EFI_BLOCK_IO_PROTOCOL *This)
{ return This==&mDisk.BlockIo ? EFI_SUCCESS : EFI_INVALID_PARAMETER; }

STATIC EFI_STATUS PublishFat (CONST UINT8 *Fat)
{
  EFI_GUID PathGuid={0xFE95FA42,0x00C4,0x4A9B,{0x84,0xD9,0x9C,0x03,0xB8,0x56,0x7A,0x01}};
  EFI_STATUS Status;
  mDisk.Image=Fat; mDisk.ImageSize=(UINTN)SHENG_KERNEL_DISK_EXPECTED_BYTES;
  mDisk.Media.MediaId=1; mDisk.Media.MediaPresent=TRUE; mDisk.Media.ReadOnly=TRUE;
  mDisk.Media.BlockSize=BLOCK_BYTES; mDisk.Media.IoAlign=1;
  mDisk.Media.LastBlock=mDisk.ImageSize/BLOCK_BYTES-1;
  mDisk.Media.LogicalBlocksPerPhysicalBlock=1; mDisk.Media.OptimalTransferLengthGranularity=1;
  mDisk.BlockIo.Revision=EFI_BLOCK_IO_PROTOCOL_REVISION3; mDisk.BlockIo.Media=&mDisk.Media;
  mDisk.BlockIo.Reset=DiskReset; mDisk.BlockIo.ReadBlocks=DiskRead;
  mDisk.BlockIo.WriteBlocks=DiskWrite; mDisk.BlockIo.FlushBlocks=DiskFlush;
  mDisk.Path.Vendor.Header.Type=HARDWARE_DEVICE_PATH; mDisk.Path.Vendor.Header.SubType=HW_VENDOR_DP;
  mDisk.Path.Vendor.Header.Length[0]=(UINT8)sizeof(VENDOR_DEVICE_PATH);
  mDisk.Path.Vendor.Header.Length[1]=(UINT8)(sizeof(VENDOR_DEVICE_PATH)>>8);
  CopyMem(&mDisk.Path.Vendor.Guid,&PathGuid,sizeof(PathGuid));
  mDisk.Path.End.Type=END_DEVICE_PATH_TYPE; mDisk.Path.End.SubType=END_ENTIRE_DEVICE_PATH_SUBTYPE;
  mDisk.Path.End.Length[0]=sizeof(EFI_DEVICE_PATH_PROTOCOL);
  Status=gBS->InstallMultipleProtocolInterfaces(&mDisk.Handle,&gEfiDevicePathProtocolGuid,&mDisk.Path,
                                               &gEfiBlockIoProtocolGuid,&mDisk.BlockIo,NULL);
  if (!EFI_ERROR(Status)) { mDiagnostic.VolumeHandle=mDisk.Handle; }
  return Status;
}

STATIC UINT64 ReadFdtCells (CONST VOID *P, INT32 Bytes)
{ return Bytes==8 ? Fdt64ToCpu(ReadUnaligned64((CONST UINT64 *)P)) : Fdt32ToCpu(ReadUnaligned32((CONST UINT32 *)P)); }

EFI_STATUS EFIAPI ShengKernelDiskDxeEntry (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_HOB_GUID_TYPE *Hob;
  CONST VOID *Fdt, *StartProp, *EndProp;
  EFI_STATUS Status;
  INT32 Chosen, StartBytes, EndBytes;
  UINTN Offset;
  UINT64 RawBytes;
  (VOID)ImageHandle; (VOID)SystemTable;
  if (mDiagnosticHandle!=NULL) { return EFI_ALREADY_STARTED; }
  mDiagnostic.Revision=SHENG_KERNEL_DISK_DIAGNOSTIC_REVISION;
  mDiagnostic.State=ShengKernelDiskInitializing;
  mDiagnostic.Status=EFI_NOT_READY; mDiagnostic.RangeStatus=EFI_NOT_READY;
  mDiagnostic.FatBytes=SHENG_KERNEL_DISK_EXPECTED_BYTES;
  CopyMem(mDiagnostic.ExpectedSha256,mExpectedSha,sizeof(mExpectedSha));
  Status=gBS->InstallMultipleProtocolInterfaces(&mDiagnosticHandle,&mDiagnosticGuid,&mDiagnostic,NULL);
  if (EFI_ERROR(Status)) { return Status; }
  Hob=GetFirstGuidHob(&mEntryArgGuid);
  if (Hob==NULL || GET_GUID_HOB_DATA_SIZE(Hob)<sizeof(UINT64)) {
    mDiagnostic.State=ShengKernelDiskNoEntryHob; Status=EFI_NOT_FOUND; goto Done;
  }
  mDiagnostic.EntryArg0=ReadUnaligned64((CONST UINT64 *)GET_GUID_HOB_DATA(Hob));
  mDiagnostic.State=ShengKernelDiskInvalidFdt;
  if (mDiagnostic.EntryArg0==0 || (mDiagnostic.EntryArg0&3)!=0) { Status=EFI_INVALID_PARAMETER; goto Done; }
  Status=CheckMemory(mDiagnostic.EntryArg0,40,FALSE);
  if (EFI_ERROR(Status)) { goto Done; }
  Fdt=(CONST VOID *)(UINTN)mDiagnostic.EntryArg0;
  if (FdtCheckHeader(Fdt)!=0) { Status=EFI_COMPROMISED_DATA; goto Done; }
  mDiagnostic.FdtBytes=FdtTotalSize(Fdt);
  if (mDiagnostic.FdtBytes<40 || mDiagnostic.FdtBytes>MAX_FDT_BYTES) { Status=EFI_BAD_BUFFER_SIZE; goto Done; }
  Status=CheckMemory(mDiagnostic.EntryArg0,mDiagnostic.FdtBytes,FALSE);
  if (EFI_ERROR(Status)) { goto Done; }
  mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_FDT_VALID;
  mDiagnostic.State=ShengKernelDiskNoInitrd;
  Chosen=FdtPathOffset(Fdt,"/chosen");
  if (Chosen<0) { Status=EFI_NOT_FOUND; goto Done; }
  StartProp=FdtGetProp(Fdt,Chosen,"linux,initrd-start",&StartBytes);
  EndProp=FdtGetProp(Fdt,Chosen,"linux,initrd-end",&EndBytes);
  if (StartProp==NULL || EndProp==NULL) { Status=EFI_NOT_FOUND; goto Done; }
  if ((StartBytes!=4 && StartBytes!=8) || (EndBytes!=4 && EndBytes!=8)) { Status=EFI_COMPROMISED_DATA; goto Done; }
  mDiagnostic.InitrdStart=ReadFdtCells(StartProp,StartBytes); mDiagnostic.InitrdEnd=ReadFdtCells(EndProp,EndBytes);
  mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_INITRD_PRESENT;
  mDiagnostic.State=ShengKernelDiskInvalidInitrdRange;
  if (mDiagnostic.InitrdEnd<=mDiagnostic.InitrdStart) { Status=EFI_BAD_BUFFER_SIZE; goto Done; }
  RawBytes=mDiagnostic.InitrdEnd-mDiagnostic.InitrdStart;
  if (RawBytes>MAX_INITRD_BYTES || RawBytes<BLOCK_BYTES) { Status=EFI_BAD_BUFFER_SIZE; goto Done; }
  mDiagnostic.State=ShengKernelDiskUnreservedInitrd;
  mDiagnostic.RangeStatus=CheckMemory(mDiagnostic.InitrdStart,RawBytes,TRUE);
  Status=mDiagnostic.RangeStatus;
  if (EFI_ERROR(Status)) { goto Done; }
  mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_RANGE_RESERVED;
  CopyMem(mDiagnostic.Prefix,(CONST VOID *)(UINTN)mDiagnostic.InitrdStart,sizeof(mDiagnostic.Prefix));
  DEBUG((DEBUG_WARN,"SHENGKERNELDISK: x0=%lx initrd=%lx-%lx first=%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x\n",
    mDiagnostic.EntryArg0,mDiagnostic.InitrdStart,mDiagnostic.InitrdEnd,
    mDiagnostic.Prefix[0],mDiagnostic.Prefix[1],mDiagnostic.Prefix[2],mDiagnostic.Prefix[3],
    mDiagnostic.Prefix[4],mDiagnostic.Prefix[5],mDiagnostic.Prefix[6],mDiagnostic.Prefix[7],
    mDiagnostic.Prefix[8],mDiagnostic.Prefix[9],mDiagnostic.Prefix[10],mDiagnostic.Prefix[11],
    mDiagnostic.Prefix[12],mDiagnostic.Prefix[13],mDiagnostic.Prefix[14],mDiagnostic.Prefix[15]));
  Status=FindFat((CONST UINT8 *)(UINTN)mDiagnostic.InitrdStart,(UINTN)RawBytes,&Offset);
  if (EFI_ERROR(Status)) {
    mDiagnostic.State=Status==EFI_CRC_ERROR ? ShengKernelDiskVolumeDigestMismatch : ShengKernelDiskVolumeNotFound;
    goto Done;
  }
  Status=PublishFat((CONST UINT8 *)(UINTN)mDiagnostic.InitrdStart+Offset);
  if (EFI_ERROR(Status)) { mDiagnostic.State=ShengKernelDiskProtocolError; goto Done; }
  mDiagnostic.Flags|=SHENG_KERNEL_DISK_FLAG_PUBLISHED;
  mDiagnostic.State=ShengKernelDiskVolumePublished;
Done:
  mDiagnostic.Status=Status;
  DEBUG((DEBUG_WARN,"SHENGKERNELDISK: state=%u status=%r range=%r flags=%x offset=%Lu bytes=%Lu scanned=%Lu prefix=%u bootsha=%u\n",
    mDiagnostic.State,Status,mDiagnostic.RangeStatus,mDiagnostic.Flags,mDiagnostic.FatOffset,mDiagnostic.FatBytes,
    mDiagnostic.ScannedBytes,mDiagnostic.PrefixCandidates,mDiagnostic.BootSectorCandidates));
  // Keep diagnostics available to the firmware app even on missing transport.
  return EFI_SUCCESS;
}
