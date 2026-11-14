/** @file
  Reserve the ABL FDT and initrd while SEC still owns the HOB list.

  Include from Sec.c after Sec.h. Call ShengKernelReserveEntry() after
  PlatformPeim() and the entry-argument HOB, before constructors or FV load.
  This file deliberately uses no FdtLib: the pinned SEC does not link it.

  Copyright (c) 2026, UniXNU contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SHENG_KERNEL_RESERVE_H_
#define SHENG_KERNEL_RESERVE_H_

#include <PiPei.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>

#define SHENG_RESERVE_MAX_INITRD  0x20000000ULL
#define SHENG_RESERVE_MAX_FDT     0x01000000ULL
#define SHENG_RESERVE_KERNEL_LO   0xA8000000ULL
#define SHENG_RESERVE_KERNEL_HI   0xB8000000ULL
#define SHENG_RESERVE_MAX_HOBS    16384U

STATIC
UINT32
ShengReserveBe32 (IN CONST UINT8 *Data)
{
  return ((UINT32)Data[0] << 24) | ((UINT32)Data[1] << 16) |
         ((UINT32)Data[2] << 8) | Data[3];
}

STATIC
BOOLEAN
ShengReserveOverlap (IN UINT64 A, IN UINT64 AEnd, IN UINT64 B, IN UINT64 BEnd)
{
  return (A < BEnd) && (B < AEnd);
}

/**
  Check that every byte is mapped ordinary DRAM and is not live firmware data.
  The board's dedicated Kernel reservation is the sole allowed reserved
  resource; secure carveouts, framebuffer, MMIO and unknown gaps are refused.
**/
STATIC
EFI_STATUS
ShengReserveCheckRange (
  IN UINT64  Base,
  IN UINT64  Length,
  IN BOOLEAN FdtRange
  )
{
  EFI_PEI_HOB_POINTERS              Hob;
  EFI_HOB_HANDOFF_INFO_TABLE       *Phit;
  EFI_HOB_RESOURCE_DESCRIPTOR      *Resource;
  EFI_HOB_MEMORY_ALLOCATION_HEADER *Allocation;
  UINT64                           End;
  UINT64                           OtherEnd;
  UINT64                           Cursor;
  UINT64                           Covered;
  UINTN                            Count;
  UINTN                            Pass;
  BOOLEAN                          Allowed;

  if ((Length == 0) || (Base > MAX_UINT64 - Length)) {
    return EFI_INVALID_PARAMETER;
  }

  End  = Base + Length;
  Phit = GetHobList ();
  // PrePi allocations descend from EfiFreeMemoryTop inside this entire heap.
  // A memory-allocation HOB alone cannot keep the PrePi allocator out of it.
  if (ShengReserveOverlap (Base, End, Phit->EfiMemoryBottom, Phit->EfiMemoryTop)) {
    return EFI_ACCESS_DENIED;
  }

  Hob.Raw = (UINT8 *)Phit;
  Count   = 0;
  while (!END_OF_HOB_LIST (Hob)) {
    if ((Hob.Header->HobLength < sizeof (EFI_HOB_GENERIC_HEADER)) ||
        (++Count > SHENG_RESERVE_MAX_HOBS))
    {
      return EFI_COMPROMISED_DATA;
    }

    if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      if (Hob.Header->HobLength < sizeof (EFI_HOB_RESOURCE_DESCRIPTOR)) {
        return EFI_COMPROMISED_DATA;
      }

      Resource = Hob.ResourceDescriptor;
      if (Resource->PhysicalStart > MAX_UINT64 - Resource->ResourceLength) {
        return EFI_COMPROMISED_DATA;
      }

      OtherEnd = Resource->PhysicalStart + Resource->ResourceLength;
      Allowed  = (Resource->ResourceType == EFI_RESOURCE_SYSTEM_MEMORY) ||
                 ((Resource->ResourceType == EFI_RESOURCE_MEMORY_RESERVED) &&
                  (Resource->PhysicalStart >= SHENG_RESERVE_KERNEL_LO) &&
                  (OtherEnd <= SHENG_RESERVE_KERNEL_HI)) ||
                 (FdtRange && (Resource->ResourceType == EFI_RESOURCE_MEMORY_RESERVED) &&
                  (Resource->PhysicalStart == 0x81A00000ULL) &&
                  (OtherEnd == 0x81A40000ULL));
      if (ShengReserveOverlap (Base, End, Resource->PhysicalStart, OtherEnd) &&
          (!Allowed ||
           ((Resource->ResourceType == EFI_RESOURCE_SYSTEM_MEMORY) &&
            ((Resource->ResourceAttribute &
             (EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED)) !=
             (EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED))) ||
           ((Resource->ResourceAttribute & EFI_RESOURCE_ATTRIBUTE_READ_PROTECTED) != 0)))
      {
        return EFI_ACCESS_DENIED;
      }
    } else if (Hob.Header->HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      if (Hob.Header->HobLength < sizeof (EFI_HOB_MEMORY_ALLOCATION)) {
        return EFI_COMPROMISED_DATA;
      }

      Allocation = &Hob.MemoryAllocation->AllocDescriptor;
      if (Allocation->MemoryBaseAddress > MAX_UINT64 - Allocation->MemoryLength) {
        return EFI_COMPROMISED_DATA;
      }

      OtherEnd = Allocation->MemoryBaseAddress + Allocation->MemoryLength;
      if (ShengReserveOverlap (Base, End, Allocation->MemoryBaseAddress, OtherEnd) &&
          (Allocation->MemoryType != EfiConventionalMemory) &&
          (Allocation->MemoryType != EfiReservedMemoryType))
      {
        // Includes firmware FD, stack, page tables, HOB buffers and FV data.
        return EFI_ACCESS_DENIED;
      }
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  // Cover adjacent resource descriptors without trusting a hole between them.
  Cursor = Base;
  for (Pass = 0; (Cursor < End) && (Pass < Count); Pass++) {
    Covered = Cursor;
    Hob.Raw = (UINT8 *)Phit;
    while (!END_OF_HOB_LIST (Hob)) {
      if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
        Resource = Hob.ResourceDescriptor;
        OtherEnd = Resource->PhysicalStart + Resource->ResourceLength;
        if ((Resource->PhysicalStart <= Cursor) && (OtherEnd > Covered)) {
          Covered = OtherEnd;
        }
      }

      Hob.Raw = GET_NEXT_HOB (Hob);
    }

    if (Covered == Cursor) {
      return EFI_NOT_FOUND;
    }

    Cursor = Covered;
  }

  return (Cursor >= End) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

STATIC
BOOLEAN
ShengReserveNameEquals (IN CONST UINT8 *Name, IN UINTN Bytes, IN CONST CHAR8 *Expected)
{
  UINTN Index;

  for (Index = 0; Index < Bytes; Index++) {
    if ((Name[Index] == 0) || (Expected[Index] == 0)) {
      return (Name[Index] == 0) && (Expected[Index] == 0);
    }

    if (Name[Index] != (UINT8)Expected[Index]) {
      return FALSE;
    }
  }

  return FALSE;
}

/** Bounds-check all structure tokens while finding the two /chosen cells. **/
STATIC
EFI_STATUS
ShengReserveFindInitrd (
  IN CONST UINT8 *Fdt,
  IN UINT32       Total,
  OUT UINT64     *Start,
  OUT UINT64     *End
  )
{
  UINT32 StructOffset;
  UINT32 StructSize;
  UINT32 StringOffset;
  UINT32 StringSize;
  UINT32 Position;
  UINT32 Token;
  UINT32 Depth;
  UINT32 Length;
  UINT32 NameOffset;
  UINT32 NameLength;
  UINT32 Index;
  BOOLEAN Chosen;
  BOOLEAN SeenChosen;
  BOOLEAN SeenRoot;
  BOOLEAN SeenStart;
  BOOLEAN SeenEnd;
  BOOLEAN IsStart;
  BOOLEAN IsEnd;
  CONST UINT8 *Name;
  CONST UINT8 *Data;
  UINT64 Value;

  StructOffset = ShengReserveBe32 (Fdt + 8);
  StringOffset = ShengReserveBe32 (Fdt + 12);
  StringSize   = ShengReserveBe32 (Fdt + 32);
  StructSize   = ShengReserveBe32 (Fdt + 36);
  if ((ShengReserveBe32 (Fdt + 20) < 17) ||
      (ShengReserveBe32 (Fdt + 24) > 17) ||
      (StructOffset < 40) || ((StructOffset & 3) != 0) ||
      (StringOffset < 40) || (StructOffset > Total) || (StringOffset > Total) ||
      (StructSize < 4) || (StructSize > Total - StructOffset) ||
      (StringSize == 0) || (StringSize > Total - StringOffset) ||
      ShengReserveOverlap (StructOffset, (UINT64)StructOffset + StructSize,
                           StringOffset, (UINT64)StringOffset + StringSize))
  {
    return EFI_COMPROMISED_DATA;
  }

  Position   = 0;
  Depth      = 0;
  Chosen     = FALSE;
  SeenChosen = FALSE;
  SeenRoot   = FALSE;
  SeenStart  = FALSE;
  SeenEnd    = FALSE;
  while (Position <= StructSize - 4) {
    Token     = ShengReserveBe32 (Fdt + StructOffset + Position);
    Position += 4;
    if (Token == 1) { // FDT_BEGIN_NODE
      if (Depth >= 64) {
        return EFI_COMPROMISED_DATA;
      }

      Name = Fdt + StructOffset + Position;
      for (NameLength = 0; NameLength < StructSize - Position; NameLength++) {
        if (Name[NameLength] == 0) {
          break;
        }
      }

      if ((NameLength == StructSize - Position) ||
          (NameLength > MAX_UINT32 - 4) ||
          (((NameLength + 4) & ~3U) > StructSize - Position))
      {
        return EFI_COMPROMISED_DATA;
      }

      if (Depth == 0) {
        if (SeenRoot || (NameLength != 0)) {
          return EFI_COMPROMISED_DATA;
        }

        SeenRoot = TRUE;
      } else if (Depth == 1) {
        Chosen = ShengReserveNameEquals (Name, NameLength + 1, "chosen");
        if (Chosen) {
          if (SeenChosen) {
            return EFI_COMPROMISED_DATA;
          }

          SeenChosen = TRUE;
        }
      }

      Position += (NameLength + 4) & ~3U;
      Depth++;
    } else if (Token == 2) { // FDT_END_NODE
      if (Depth == 0) {
        return EFI_COMPROMISED_DATA;
      }

      if (Depth == 2) {
        Chosen = FALSE;
      }

      Depth--;
    } else if (Token == 3) { // FDT_PROP
      if ((Depth == 0) || (StructSize - Position < 8)) {
        return EFI_COMPROMISED_DATA;
      }

      Length     = ShengReserveBe32 (Fdt + StructOffset + Position);
      NameOffset = ShengReserveBe32 (Fdt + StructOffset + Position + 4);
      Position  += 8;
      if ((NameOffset >= StringSize) || (Length > MAX_UINT32 - 3) ||
          (((Length + 3) & ~3U) > StructSize - Position))
      {
        return EFI_COMPROMISED_DATA;
      }

      Name = Fdt + StringOffset + NameOffset;
      for (Index = 0; Index < StringSize - NameOffset; Index++) {
        if (Name[Index] == 0) {
          break;
        }
      }

      if (Index == StringSize - NameOffset) {
        return EFI_COMPROMISED_DATA;
      }

      if (Chosen && (Depth == 2)) {
        IsStart = ShengReserveNameEquals (Name, Index + 1, "linux,initrd-start");
        IsEnd   = ShengReserveNameEquals (Name, Index + 1, "linux,initrd-end");
        if (IsStart || IsEnd) {
          if (((Length != 4) && (Length != 8)) ||
              (IsStart && SeenStart) || (IsEnd && SeenEnd))
          {
            return EFI_COMPROMISED_DATA;
          }

          Data  = Fdt + StructOffset + Position;
          Value = ShengReserveBe32 (Data);
          if (Length == 8) {
            Value = (Value << 32) | ShengReserveBe32 (Data + 4);
          }

          if (IsStart) {
            *Start    = Value;
            SeenStart = TRUE;
          } else {
            *End    = Value;
            SeenEnd = TRUE;
          }
        }
      }

      Position += (Length + 3) & ~3U;
    } else if (Token == 9) { // FDT_END
      if (!SeenRoot || (Depth != 0)) {
        return EFI_COMPROMISED_DATA;
      }

      return (SeenStart && SeenEnd) ? EFI_SUCCESS : EFI_NOT_FOUND;
    } else if (Token != 4) { // FDT_NOP
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_COMPROMISED_DATA;
}

STATIC
EFI_STATUS
ShengReservePages (IN UINT64 Base, IN UINT64 Length, IN BOOLEAN FdtRange)
{
  EFI_STATUS                        Status;
  EFI_PEI_HOB_POINTERS              Hob;
  EFI_HOB_MEMORY_ALLOCATION_HEADER *Allocation;
  UINT64                            PageBase;
  UINT64                            PageEnd;
  UINT64                            OtherBase;
  UINT64                            OtherEnd;
  UINT64                            Cursor;
  UINT64                            Next;
  UINTN                             Pass;

  if ((Length == 0) || (Base > MAX_UINT64 - Length) ||
      (Base + Length > MAX_UINT64 - EFI_PAGE_MASK))
  {
    return EFI_INVALID_PARAMETER;
  }

  PageBase = Base & ~((UINT64)EFI_PAGE_MASK);
  PageEnd  = (Base + Length + EFI_PAGE_MASK) & ~((UINT64)EFI_PAGE_MASK);
  Status   = ShengReserveCheckRange (PageBase, PageEnd - PageBase, FdtRange);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // MemoryPeim also emits allocation HOBs whose type is Conventional for
  // entire DRAM regions. DXE claims allocation HOBs in order through GCD;
  // appending a Reserved HOB over an already claimed Conventional HOB would
  // fail that claim. Subtract this range from those Conventional HOBs first.
  Hob.Raw = GetHobList ();
  while (!END_OF_HOB_LIST (Hob)) {
    if (Hob.Header->HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      Allocation = &Hob.MemoryAllocation->AllocDescriptor;
      OtherBase  = Allocation->MemoryBaseAddress;
      OtherEnd   = OtherBase + Allocation->MemoryLength;
      if ((Allocation->MemoryType == EfiConventionalMemory) &&
          ShengReserveOverlap (PageBase, PageEnd, OtherBase, OtherEnd))
      {
        if (OtherBase < PageBase) {
          Allocation->MemoryLength = PageBase - OtherBase;
          if (OtherEnd > PageEnd) {
            BuildMemoryAllocationHob (PageEnd, OtherEnd - PageEnd, EfiConventionalMemory);
          }
        } else if (OtherEnd > PageEnd) {
          Allocation->MemoryBaseAddress = PageEnd;
          Allocation->MemoryLength      = OtherEnd - PageEnd;
        } else {
          Hob.Header->HobType = EFI_HOB_TYPE_UNUSED;
        }
      }
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  // Page rounding can touch an earlier Reserved HOB (for example the FDT's
  // final page). Reserve uncovered pieces only, so no GCD claim overlaps.
  Cursor = PageBase;
  for (Pass = 0; (Cursor < PageEnd) && (Pass < SHENG_RESERVE_MAX_HOBS); Pass++) {
    Next    = PageEnd;
    Hob.Raw = GetHobList ();
    while (!END_OF_HOB_LIST (Hob)) {
      if (Hob.Header->HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
        Allocation = &Hob.MemoryAllocation->AllocDescriptor;
        OtherBase  = Allocation->MemoryBaseAddress;
        OtherEnd   = OtherBase + Allocation->MemoryLength;
        if ((Allocation->MemoryType == EfiReservedMemoryType) && (OtherEnd > Cursor)) {
          if (OtherBase <= Cursor) {
            Cursor = MIN (OtherEnd, PageEnd);
            break;
          }

          Next = MIN (Next, OtherBase);
        }
      }

      Hob.Raw = GET_NEXT_HOB (Hob);
    }

    if (!END_OF_HOB_LIST (Hob)) {
      continue;
    }

    BuildMemoryAllocationHob (Cursor, Next - Cursor, EfiReservedMemoryType);
    Cursor = Next;
  }

  if (Cursor != PageEnd) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ShengKernelReserveEntry (IN UINT64 EntryArg0)
{
  EFI_STATUS   Status;
  EFI_STATUS   ParseStatus;
  CONST UINT8 *Fdt;
  UINT32       Total;
  UINT64       Start;
  UINT64       End;

  if ((EntryArg0 == 0) || ((EntryArg0 & 3) != 0)) {
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  Status = ShengReserveCheckRange (EntryArg0, 40, TRUE);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Fdt   = (CONST UINT8 *)(UINTN)EntryArg0;
  Total = ShengReserveBe32 (Fdt + 4);
  if ((ShengReserveBe32 (Fdt) != 0xD00DFEEDU) || (Total < 40) ||
      (Total > SHENG_RESERVE_MAX_FDT))
  {
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

  Status = ShengReserveCheckRange (EntryArg0, Total, TRUE);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Start       = 0;
  End         = 0;
  ParseStatus = ShengReserveFindInitrd (Fdt, Total, &Start, &End);
  // Keep even a FDT with no initrd safe for the DXE diagnostic path.
  Status = ShengReservePages (EntryArg0, Total, TRUE);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  if (EFI_ERROR (ParseStatus)) {
    Status = ParseStatus;
    goto Done;
  }

  if ((End <= Start) || (End - Start > SHENG_RESERVE_MAX_INITRD) ||
      ShengReserveOverlap (Start, End, EntryArg0, EntryArg0 + Total))
  {
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

  Status = ShengReservePages (Start, End - Start, FALSE);
  DEBUG ((DEBUG_WARN, "SHENGRESERVE: FDT=0x%lx bytes=0x%x initrd=0x%lx-0x%lx %r\n",
          EntryArg0, Total, Start, End, Status));
Done:
  DEBUG ((DEBUG_WARN, "SHENGRESERVE: x0=0x%lx reservation=%r\n", EntryArg0, Status));
  return Status;
}

#endif
