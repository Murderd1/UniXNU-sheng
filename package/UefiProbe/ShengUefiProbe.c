/** @file
  Standalone sheng UEFI probe. It stays in boot services without opening a
  filesystem, starting another image or accessing an OS payload. The firmware
  probe build replaces the normal UniXNU application with this application.

  Copyright (c) 2026, UniXNU contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SerialIo.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextOut.h>

#ifndef SHENG_UEFI_PROBE_BUILD_ID
#define SHENG_UEFI_PROBE_BUILD_ID "unversioned"
#endif

#define PROBE_SECOND      10000000ULL
#define PROBE_MIN_TICKS   300U
#define PROBE_MAX_WIDTH   1440U
#define PROBE_MAX_HEIGHT  900U
#define PROBE_LINE_COUNT  19U

typedef struct {
  CHAR8    Character;
  UINT8    Rows[7];
} PROBE_GLYPH;

// Small embedded font keeps the probe independent of the normal UI library.
STATIC CONST PROBE_GLYPH  mGlyphs[] = {
  { ' ', { 0, 0, 0, 0, 0, 0, 0 } },
  { '0', { 14, 17, 19, 21, 25, 17, 14 } },
  { '1', { 4, 12, 4, 4, 4, 4, 14 } },
  { '2', { 14, 17, 1, 2, 4, 8, 31 } },
  { '3', { 30, 1, 1, 14, 1, 1, 30 } },
  { '4', { 2, 6, 10, 18, 31, 2, 2 } },
  { '5', { 31, 16, 16, 30, 1, 1, 30 } },
  { '6', { 14, 16, 16, 30, 17, 17, 14 } },
  { '7', { 31, 1, 2, 4, 8, 8, 8 } },
  { '8', { 14, 17, 17, 14, 17, 17, 14 } },
  { '9', { 14, 17, 17, 15, 1, 1, 14 } },
  { 'A', { 14, 17, 17, 31, 17, 17, 17 } },
  { 'B', { 30, 17, 17, 30, 17, 17, 30 } },
  { 'C', { 14, 17, 16, 16, 16, 17, 14 } },
  { 'D', { 30, 17, 17, 17, 17, 17, 30 } },
  { 'E', { 31, 16, 16, 30, 16, 16, 31 } },
  { 'F', { 31, 16, 16, 30, 16, 16, 16 } },
  { 'G', { 14, 17, 16, 23, 17, 17, 15 } },
  { 'H', { 17, 17, 17, 31, 17, 17, 17 } },
  { 'I', { 14, 4, 4, 4, 4, 4, 14 } },
  { 'J', { 7, 2, 2, 2, 2, 18, 12 } },
  { 'K', { 17, 18, 20, 24, 20, 18, 17 } },
  { 'L', { 16, 16, 16, 16, 16, 16, 31 } },
  { 'M', { 17, 27, 21, 21, 17, 17, 17 } },
  { 'N', { 17, 25, 21, 19, 17, 17, 17 } },
  { 'O', { 14, 17, 17, 17, 17, 17, 14 } },
  { 'P', { 30, 17, 17, 30, 16, 16, 16 } },
  { 'Q', { 14, 17, 17, 17, 21, 18, 13 } },
  { 'R', { 30, 17, 17, 30, 20, 18, 17 } },
  { 'S', { 15, 16, 16, 14, 1, 1, 30 } },
  { 'T', { 31, 4, 4, 4, 4, 4, 4 } },
  { 'U', { 17, 17, 17, 17, 17, 17, 14 } },
  { 'V', { 17, 17, 17, 17, 17, 10, 4 } },
  { 'W', { 17, 17, 17, 21, 21, 21, 10 } },
  { 'X', { 17, 17, 10, 4, 10, 17, 17 } },
  { 'Y', { 17, 17, 10, 4, 4, 4, 4 } },
  { 'Z', { 31, 1, 2, 4, 8, 16, 31 } },
  { ':', { 0, 4, 4, 0, 4, 4, 0 } },
  { '.', { 0, 0, 0, 0, 0, 4, 4 } },
  { '-', { 0, 0, 0, 31, 0, 0, 0 } },
  { '_', { 0, 0, 0, 0, 0, 0, 31 } },
  { '/', { 1, 2, 2, 4, 8, 8, 16 } },
  { '=', { 0, 0, 31, 0, 31, 0, 0 } },
  { '+', { 0, 4, 4, 31, 4, 4, 0 } },
  { '?', { 14, 17, 1, 2, 4, 0, 4 } }
};

STATIC EFI_GRAPHICS_OUTPUT_PROTOCOL  *mGop;
STATIC EFI_GRAPHICS_OUTPUT_BLT_PIXEL *mCanvas;
STATIC EFI_SERIAL_IO_PROTOCOL       *mSerial;
STATIC UINTN                        mWidth;
STATIC UINTN                        mHeight;
STATIC UINTN                        mScale;
STATIC UINTN                        mTicks;
STATIC UINTN                        mKeyCount;
STATIC UINTN                        mResetDeadline;
STATIC BOOLEAN                      mInputAvailable;
STATIC BOOLEAN                      mInputSeen;
STATIC BOOLEAN                      mGopDrawn;
STATIC BOOLEAN                      mWatchdogDisabled;
STATIC BOOLEAN                      mTimerReady;
STATIC BOOLEAN                      mFault;
STATIC CHAR8                        mLastKey[72] = "NONE - PRESS A KEY OR A VOLUME BUTTON";
STATIC CHAR8                        mFailure[96] = "NONE";
STATIC CONST EFI_GRAPHICS_OUTPUT_BLT_PIXEL mBackground = { 24, 18, 12, 0 };
STATIC CONST EFI_GRAPHICS_OUTPUT_BLT_PIXEL mText       = { 232, 232, 232, 0 };
STATIC CONST EFI_GRAPHICS_OUTPUT_BLT_PIXEL mAccent     = { 196, 218, 70, 0 };

STATIC
VOID
EFIAPI
ProbeLog (
  IN CONST CHAR8  *Format,
  ...
  )
{
  VA_LIST     Args;
  CHAR8       Line[256];
  UINTN       Length;
  EFI_STATUS  Status;

  Length = AsciiSPrint (Line, sizeof (Line), "SHENGUEFI: ");
  VA_START (Args, Format);
  Length += AsciiVSPrint (Line + Length, sizeof (Line) - Length - 2, Format, Args);
  VA_END (Args);
  Line[Length++] = '\r';
  Line[Length++] = '\n';
  Line[Length]   = '\0';
  // The pinned platform's DEBUG mask includes WARN but excludes INFO.
  DEBUG ((DEBUG_WARN, "%a", Line));
  if (mSerial != NULL) {
    // A 256-byte line needs about 23 ms at 115200 baud. Bound each write to
    // 50 ms, and never retry a failed write or block the heartbeat on logging.
    Status = mSerial->Write (mSerial, &Length, Line);
    if (EFI_ERROR (Status)) {
      mSerial = NULL;
    }
  }
}

STATIC
VOID
InitSerial (
  VOID
  )
{
  EFI_SERIAL_IO_MODE  *Mode;
  EFI_STATUS         Status;

  Status = gBS->LocateProtocol (&gEfiSerialIoProtocolGuid, NULL, (VOID **)&mSerial);
  if (EFI_ERROR (Status) || (mSerial == NULL) || (mSerial->Mode == NULL)) {
    mSerial = NULL;
    return;
  }

  Mode   = mSerial->Mode;
  Status = mSerial->SetAttributes (
                      mSerial,
                      Mode->BaudRate,
                      Mode->ReceiveFifoDepth,
                      50000,
                      (EFI_PARITY_TYPE)Mode->Parity,
                      (UINT8)Mode->DataBits,
                      (EFI_STOP_BITS_TYPE)Mode->StopBits
                      );
  if (EFI_ERROR (Status)) {
    mSerial = NULL;
  }
}

STATIC
VOID
RecordFailure (
  IN CONST CHAR8  *Reason,
  IN EFI_STATUS   Status
  )
{
  mFault = TRUE;
  AsciiSPrint (mFailure, sizeof (mFailure), "%a %r", Reason, Status);
  ProbeLog ("FAIL %a", mFailure);
}

STATIC
VOID
Rectangle (
  IN UINTN                                X,
  IN UINTN                                Y,
  IN UINTN                                Width,
  IN UINTN                                Height,
  IN CONST EFI_GRAPHICS_OUTPUT_BLT_PIXEL   *Color
  )
{
  UINTN  Column;
  UINTN  Row;

  for (Row = Y; (Row < Y + Height) && (Row < mHeight); Row++) {
    for (Column = X; (Column < X + Width) && (Column < mWidth); Column++) {
      mCanvas[Row * mWidth + Column] = *Color;
    }
  }
}

STATIC
VOID
DrawText (
  IN UINTN        Line,
  IN CONST CHAR8  *Text
  )
{
  CONST UINT8  *Rows;
  UINTN        Character;
  UINTN        Glyph;
  UINTN        Row;
  UINTN        Column;
  UINTN        X;
  UINTN        Y;
  CHAR8        Code;

  X = 12;
  Y = 12 + Line * (9 * mScale);
  for (Character = 0; (Text[Character] != '\0') && (X + 5 * mScale <= mWidth); Character++) {
    Code = Text[Character];
    if ((Code >= 'a') && (Code <= 'z')) {
      Code = (CHAR8)(Code - 'a' + 'A');
    }

    Rows = mGlyphs[sizeof (mGlyphs) / sizeof (mGlyphs[0]) - 1].Rows;
    for (Glyph = 0; Glyph < sizeof (mGlyphs) / sizeof (mGlyphs[0]); Glyph++) {
      if (mGlyphs[Glyph].Character == Code) {
        Rows = mGlyphs[Glyph].Rows;
        break;
      }
    }

    for (Row = 0; Row < 7; Row++) {
      for (Column = 0; Column < 5; Column++) {
        if ((Rows[Row] & (1U << (4 - Column))) != 0) {
          Rectangle (X + Column * mScale, Y + Row * mScale, mScale, mScale,
                     (Line == 0) ? &mAccent : &mText);
        }
      }
    }

    X += 6 * mScale;
  }
}

STATIC
EFI_STATUS
InitGraphics (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = gBS->HandleProtocol (gST->ConsoleOutHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **)&mGop);
  if (EFI_ERROR (Status)) {
    Status = gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&mGop);
  }

  if (EFI_ERROR (Status) || (mGop == NULL) || (mGop->Mode == NULL) ||
      (mGop->Mode->Info == NULL) || (mGop->Blt == NULL))
  {
    mGop = NULL;
    return EFI_NOT_FOUND;
  }

  mWidth  = mGop->Mode->Info->HorizontalResolution;
  mHeight = mGop->Mode->Info->VerticalResolution;
  if ((mWidth < 360) || (mHeight < 220)) {
    mGop = NULL;
    return EFI_UNSUPPORTED;
  }

  if (mWidth > PROBE_MAX_WIDTH) {
    mWidth = PROBE_MAX_WIDTH;
  }

  if (mHeight > PROBE_MAX_HEIGHT) {
    mHeight = PROBE_MAX_HEIGHT;
  }

  mScale = ((mWidth >= 1080) && (mHeight >= 600)) ? 3 :
           (((mWidth >= 720) && (mHeight >= 400)) ? 2 : 1);
  mCanvas = AllocateZeroPool (mWidth * mHeight * sizeof (*mCanvas));
  if (mCanvas == NULL) {
    mGop = NULL;
    return EFI_OUT_OF_RESOURCES;
  }

  // Preserve the existing GOP mode and use Blt, including on PixelBltOnly GOPs.
  Status = mGop->Blt (mGop, (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)&mBackground,
                     EfiBltVideoFill, 0, 0, 0, 0,
                     mGop->Mode->Info->HorizontalResolution,
                     mGop->Mode->Info->VerticalResolution, 0);
  if (EFI_ERROR (Status)) {
    FreePool (mCanvas);
    mCanvas = NULL;
    mGop    = NULL;
  }

  return Status;
}

STATIC
BOOLEAN
RunChecksMet (
  VOID
  )
{
  return (BOOLEAN)(mGopDrawn && mInputSeen && mWatchdogDisabled &&
                   mTimerReady && !mFault && (mTicks >= PROBE_MIN_TICKS));
}

STATIC
VOID
DrawScreen (
  VOID
  )
{
  CHAR8       Lines[PROBE_LINE_COUNT][112];
  CHAR16      ConsoleLine[120];
  UINTN       Line;
  UINTN       Index;
  UINTN       DestinationX;
  UINTN       DestinationY;
  EFI_STATUS  Status;

  AsciiSPrint (Lines[0], sizeof (Lines[0]), "SHENG UEFI - STAGE 1 PROBE");
  AsciiSPrint (Lines[1], sizeof (Lines[1]), "BUILD: %a", SHENG_UEFI_PROBE_BUILD_ID);
  AsciiSPrint (Lines[2], sizeof (Lines[2]), "STAGE: APP_ENTRY / MENU_READY");
  AsciiSPrint (Lines[3], sizeof (Lines[3]), "HEARTBEAT: %u  %a", (UINT32)mTicks, (mTicks & 1) ? "+" : "-");
  AsciiSPrint (Lines[4], sizeof (Lines[4]), "OBSERVED 1-SECOND TICKS: %u / 300", (UINT32)mTicks);
  AsciiSPrint (Lines[5], sizeof (Lines[5]), "GOP: %a", (mGop != NULL) ? "DRAWING - VERIFY SCREEN VISUALLY" : "MISSING OR FAILED - NOT READY");
  AsciiSPrint (Lines[6], sizeof (Lines[6]), "INPUT: %a", mInputSeen ? "KEY RECEIVED" :
              (mInputAvailable ? "WAITING FOR A REAL KEY" : "MISSING - NOT READY"));
  AsciiSPrint (Lines[7], sizeof (Lines[7]), "KEYS: %u  LAST: %a", (UINT32)mKeyCount, mLastKey);
  AsciiSPrint (Lines[8], sizeof (Lines[8]), "WATCHDOG: %a  TIMER: %a", mWatchdogDisabled ? "DISABLED" : "FAILED",
              mTimerReady ? "RUNNING" : "FAILED");
  AsciiSPrint (Lines[9], sizeof (Lines[9]), "FAULT: %a", mFailure);
  AsciiSPrint (Lines[10], sizeof (Lines[10]), "%a", RunChecksMet () ?
              "RUN CHECKS MET - SAVE THIS SCREEN" : "RUN CHECKS PENDING - DO NOT MARK PASSED");
  AsciiSPrint (Lines[11], sizeof (Lines[11]), "C: REDRAW   R THEN Y: ORDINARY RESTART");
  AsciiSPrint (Lines[12], sizeof (Lines[12]), "%a", (mResetDeadline != 0) ?
              "RESTART ARMED: Y CONFIRMS - ANY OTHER KEY CANCELS" : "RESTART DOES NOT GUARANTEE FASTBOOT ENTRY");
  AsciiSPrint (Lines[13], sizeof (Lines[13]), "USE THE HARDWARE KEY COMBINATION FOR FASTBOOT");
  AsciiSPrint (Lines[14], sizeof (Lines[14]), "STAYS IN UEFI - NO AUTOMATIC OS START");
  AsciiSPrint (Lines[15], sizeof (Lines[15]), "HARDWARE ACCEPTANCE: ONE RUN + 5 MIN + FASTBOOT RETURN");
  AsciiSPrint (Lines[16], sizeof (Lines[16]), "CHECK VISIBLE HEARTBEAT AND KEY RESPONSE EACH RUN");
  AsciiSPrint (Lines[17], sizeof (Lines[17]), "VERIFY RETURN TO FASTBOOT AND HOST DETECTION");
  AsciiSPrint (Lines[18], sizeof (Lines[18]), "TIMER TICKS ARE A CONSERVATIVE MINIMUM DURATION");

  if ((mGop != NULL) && (mCanvas != NULL)) {
    for (Index = 0; Index < mWidth * mHeight; Index++) {
      mCanvas[Index] = mBackground;
    }

    for (Line = 0; Line < PROBE_LINE_COUNT; Line++) {
      DrawText (Line, Lines[Line]);
    }

    DestinationX = (mGop->Mode->Info->HorizontalResolution - mWidth) / 2;
    DestinationY = (mGop->Mode->Info->VerticalResolution - mHeight) / 2;
    Status       = mGop->Blt (mGop, mCanvas, EfiBltBufferToVideo, 0, 0,
                             DestinationX, DestinationY, mWidth, mHeight,
                             mWidth * sizeof (*mCanvas));
    if (!EFI_ERROR (Status)) {
      if (!mGopDrawn) {
        mGopDrawn = TRUE;
        ProbeLog ("GOP_READY width=%u height=%u", (UINT32)mGop->Mode->Info->HorizontalResolution,
                  (UINT32)mGop->Mode->Info->VerticalResolution);
      }

      return;
    }

    RecordFailure ("GOP_BLT_FAILED", Status);
    mGopDrawn = FALSE;
    mGop     = NULL;
    FreePool (mCanvas);
    mCanvas = NULL;
    AsciiSPrint (Lines[5], sizeof (Lines[5]), "GOP: DRAW FAILED - NOT READY");
    AsciiSPrint (Lines[9], sizeof (Lines[9]), "FAULT: %a", mFailure);
    AsciiSPrint (Lines[10], sizeof (Lines[10]), "RUN CHECKS FAILED - DO NOT MARK PASSED");
  }

  if (gST->ConOut != NULL) {
    gST->ConOut->SetCursorPosition (gST->ConOut, 0, 0);
    for (Line = 0; Line < PROBE_LINE_COUNT; Line++) {
      UnicodeSPrint (ConsoleLine, sizeof (ConsoleLine), L"%a\r\n", Lines[Line]);
      gST->ConOut->OutputString (gST->ConOut, ConsoleLine);
    }
  }
}

STATIC
VOID
HandleKey (
  IN CONST EFI_INPUT_KEY  *Key
  )
{
  BOOLEAN  ConfirmReset;

  mInputSeen = TRUE;
  mKeyCount++;
  AsciiSPrint (mLastKey, sizeof (mLastKey), "SCAN %04X CHAR %04X", Key->ScanCode, Key->UnicodeChar);
  ProbeLog ("INPUT_KEY count=%u scan=%04x char=%04x", (UINT32)mKeyCount, Key->ScanCode, Key->UnicodeChar);
  ConfirmReset = (BOOLEAN)((mResetDeadline != 0) &&
                          ((Key->UnicodeChar == L'y') || (Key->UnicodeChar == L'Y')));
  if (ConfirmReset) {
    mResetDeadline = 0;
    ProbeLog ("WARM_RESET requested - target is platform default, not a Fastboot guarantee");
    gRT->ResetSystem (EfiResetWarm, EFI_SUCCESS, 0, NULL);
    RecordFailure ("RESET_RETURNED", EFI_DEVICE_ERROR);
  } else if ((Key->UnicodeChar == L'r') || (Key->UnicodeChar == L'R')) {
    mResetDeadline = mTicks + 10;
    ProbeLog ("RESET_ARMED confirm Y within 10 timer ticks");
  } else {
    mResetDeadline = 0;
    if ((Key->UnicodeChar == L'c') || (Key->UnicodeChar == L'C')) {
      ProbeLog ("REDRAW requested");
    }
  }
}

EFI_STATUS
EFIAPI
ShengUefiProbeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS     Status;
  EFI_EVENT      Timer;
  EFI_EVENT      Events[2];
  UINTN          EventCount;
  UINTN          Signaled;
  EFI_INPUT_KEY  Key;
  BOOLEAN        ReportedRunChecks;

  (VOID)ImageHandle;
  (VOID)SystemTable;
  InitSerial ();
  ProbeLog ("APP_ENTRY build=%a - DXE/BDS reached application", SHENG_UEFI_PROBE_BUILD_ID);
  Status            = gBS->SetWatchdogTimer (0, 0, 0, NULL);
  mWatchdogDisabled = (BOOLEAN)!EFI_ERROR (Status);
  if (!mWatchdogDisabled) {
    RecordFailure ("WATCHDOG_DISABLE_FAILED", Status);
  }

  if (gST->ConOut != NULL) {
    gST->ConOut->SetAttribute (gST->ConOut, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
    gST->ConOut->ClearScreen (gST->ConOut);
    ProbeLog ("TEXT_CONSOLE_PRESENT");
  } else {
    ProbeLog ("TEXT_CONSOLE_MISSING - using embedded GOP text if available");
  }

  Status = InitGraphics ();
  if (EFI_ERROR (Status)) {
    RecordFailure ("GOP_INIT_FAILED", Status);
  }

  mInputAvailable = (BOOLEAN)((gST->ConIn != NULL) && (gST->ConIn->WaitForKey != NULL));
  ProbeLog ("INPUT_PROTOCOL %a - input acceptance requires a received key",
            mInputAvailable ? "present" : "missing");
  Timer  = NULL;
  Status = gBS->CreateEvent (EVT_TIMER, TPL_CALLBACK, NULL, NULL, &Timer);
  if (!EFI_ERROR (Status)) {
    Status = gBS->SetTimer (Timer, TimerPeriodic, PROBE_SECOND);
  }

  mTimerReady = (BOOLEAN)!EFI_ERROR (Status);
  if (!mTimerReady) {
    RecordFailure ("TIMER_INIT_FAILED", Status);
    if (Timer != NULL) {
      gBS->CloseEvent (Timer);
    }
  }

  DrawScreen ();
  ProbeLog ("MENU_READY build=%a gop=%u input=%u timer=%u - no OS will be started",
            SHENG_UEFI_PROBE_BUILD_ID, mGopDrawn, mInputAvailable, mTimerReady);
  EventCount        = 0;
  ReportedRunChecks = FALSE;
  if (mTimerReady) {
    Events[EventCount++] = Timer;
  }

  if (mInputAvailable) {
    Events[EventCount++] = gST->ConIn->WaitForKey;
  }

  for ( ; ;) {
    if ((EventCount == 0) || !mTimerReady) {
      // A failed timer must not return control to a BDS fallback OS option.
      gBS->Stall (1000000);
      if (mInputAvailable && !EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key))) {
        HandleKey (&Key);
      }

      DrawScreen ();
      continue;
    }

    Status = gBS->WaitForEvent (EventCount, Events, &Signaled);
    if (EFI_ERROR (Status)) {
      RecordFailure ("WAIT_FOR_EVENT_FAILED", Status);
      mTimerReady = FALSE;
      DrawScreen ();
      continue;
    }

    if (Signaled == 0) {
      // Coalesced timer events undercount elapsed time rather than approving
      // the five-minute run early. Key events never increment this counter.
      mTicks++;
      if ((mResetDeadline != 0) && (mTicks >= mResetDeadline)) {
        mResetDeadline = 0;
        ProbeLog ("RESET_CANCELLED timeout");
      }

      ProbeLog ("HEARTBEAT ticks=%u keys=%u gop=%u", (UINT32)mTicks, (UINT32)mKeyCount, mGopDrawn);
      if (mTicks == PROBE_MIN_TICKS) {
        ProbeLog ("HOLD_300_TICKS input=%u gop=%u - cold boot and Fastboot checks remain manual", mInputSeen, mGopDrawn);
      }
    } else {
      Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
      if (!EFI_ERROR (Status)) {
        HandleKey (&Key);
      } else if (Status != EFI_NOT_READY) {
        RecordFailure ("INPUT_READ_FAILED", Status);
      }
    }

    DrawScreen ();
    if (RunChecksMet () && !ReportedRunChecks) {
      ProbeLog ("RUN_CHECKS_MET - verify visible output and Fastboot return manually");
      ReportedRunChecks = TRUE;
    }
  }
}
