#!/usr/bin/env python3
"""Exercise the real probe against mocked UEFI services and real EDK II headers.

This checks application behavior on the host. It does not boot a firmware image
or establish display, timer, key or reset behavior on the tablet.
"""
import argparse
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#undef NULL
#include "ShengUefiProbe.c"

EFI_BOOT_SERVICES *gBS;
EFI_SYSTEM_TABLE *gST;
EFI_RUNTIME_SERVICES *gRT;
EFI_GUID gEfiGraphicsOutputProtocolGuid = {1};
EFI_GUID gEfiSerialIoProtocolGuid = {2};
static EFI_BOOT_SERVICES services;
static EFI_SYSTEM_TABLE system_table;
static EFI_RUNTIME_SERVICES runtime;
static EFI_SIMPLE_TEXT_INPUT_PROTOCOL input;
static EFI_GRAPHICS_OUTPUT_PROTOCOL graphics;
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE mode;
static EFI_GRAPHICS_OUTPUT_MODE_INFORMATION info;
static jmp_buf escape;
static unsigned step, stop_step, ticks, keys, resets, blits;
static int no_gop, no_input, fail_watchdog, fail_timer, fail_blt, fail_wait;
static char log_text[262144];
static size_t log_length;

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

// Convert the small PrintLib format subset used by the application. UEFI %a
// denotes an ASCII string and %r a status value, unlike the C printf formats.
UINTN EFIAPI AsciiVSPrint(CHAR8 *out, UINTN size, CONST CHAR8 *format, VA_LIST args) {
  char converted[512]; size_t i, n=0; int count;
  for (i=0; format[i] && n+5 < sizeof(converted); i++) {
    if (format[i]=='%' && format[i+1]=='a') {converted[n++]='%'; converted[n++]='s'; i++;}
    else if (format[i]=='%' && format[i+1]=='r') {memcpy(converted+n,"%llx",4); n+=4; i++;}
    else converted[n++]=format[i];
  }
  converted[n]=0;
  count=vsnprintf(out,(size_t)size,converted,args);
  return count<0 ? 0 : (UINTN)((size_t)count<size ? count : (size_t)size-1);
}
UINTN EFIAPI AsciiSPrint(CHAR8 *out, UINTN size, CONST CHAR8 *format, ...) {
  VA_LIST args; UINTN n; VA_START(args,format); n=AsciiVSPrint(out,size,format,args); VA_END(args); return n;
}
UINTN EFIAPI UnicodeSPrint(CHAR16 *out, UINTN size, CONST CHAR16 *format, ...) {
  VA_LIST args; CONST char *text; UINTN i=0; (void)format;
  VA_START(args,format); text=VA_ARG(args,CONST char*); VA_END(args);
  while (text[i] && (i+1)*sizeof(*out)<size) {out[i]=(CHAR16)text[i]; i++;} out[i]=0; return i;
}
VOID *EFIAPI AllocateZeroPool(UINTN size) {return calloc(1,(size_t)size);}
VOID EFIAPI FreePool(VOID *buffer) {free(buffer);}
BOOLEAN EFIAPI DebugPrintEnabled(VOID) {return TRUE;}
BOOLEAN EFIAPI DebugPrintLevelEnabled(CONST UINTN level) {(void)level; return TRUE;}
VOID EFIAPI DebugPrint(UINTN level, CONST CHAR8 *format, ...) {
  VA_LIST args; const char *line; size_t n; (void)level; (void)format;
  VA_START(args,format); line=VA_ARG(args,const char*); VA_END(args);
  n=strlen(line); CHECK(n+log_length+1<sizeof(log_text)); memcpy(log_text+log_length,line,n+1); log_length+=n;
}

static EFI_STATUS EFIAPI locate(EFI_GUID *guid, VOID *registration, VOID **out) {
  (void)registration;
  if (guid==&gEfiGraphicsOutputProtocolGuid && !no_gop) {*out=&graphics; return EFI_SUCCESS;}
  *out=NULL; return EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI handle(EFI_HANDLE h, EFI_GUID *guid, VOID **out) {(void)h; return locate(guid,NULL,out);}
static EFI_STATUS EFIAPI watchdog(UINTN timeout, UINT64 code, UINTN size, CHAR16 *data) {
  CHECK(timeout==0); (void)code; (void)size; (void)data; return fail_watchdog ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS EFIAPI create(UINT32 type, EFI_TPL tpl, EFI_EVENT_NOTIFY notify, VOID *context, EFI_EVENT *event) {
  CHECK(type==EVT_TIMER); (void)tpl; (void)notify; (void)context; *event=(EFI_EVENT)(UINTN)1; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI timer(EFI_EVENT event, EFI_TIMER_DELAY type, UINT64 period) {
  (void)event; CHECK(type==TimerPeriodic && period==10000000ULL); return fail_timer ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS EFIAPI close_event(EFI_EVENT event) {(void)event; return EFI_SUCCESS;}
static EFI_STATUS EFIAPI wait_event(UINTN count, EFI_EVENT *events, UINTN *signaled) {
  (void)events; CHECK(count>=1 && count<=2);
  if (step++>=stop_step) longjmp(escape,1);
  if (fail_wait) return EFI_DEVICE_ERROR;
  if (keys) {CHECK(!no_input && count==2); keys--; *signaled=1;} else {*signaled=0; ticks++;}
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI stall(UINTN microseconds) {
  CHECK(microseconds==1000000); if (step++>=stop_step) longjmp(escape,1); return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI read_key(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *self, EFI_INPUT_KEY *key) {
  (void)self; key->UnicodeChar=L'c'; key->ScanCode=0; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI blt(EFI_GRAPHICS_OUTPUT_PROTOCOL *self, EFI_GRAPHICS_OUTPUT_BLT_PIXEL *buffer,
  EFI_GRAPHICS_OUTPUT_BLT_OPERATION operation, UINTN sx, UINTN sy, UINTN dx, UINTN dy, UINTN width, UINTN height, UINTN delta) {
  (void)self; (void)sx; (void)sy; (void)dx; (void)dy; (void)delta;
  CHECK(buffer && width && height); CHECK(operation==EfiBltVideoFill || operation==EfiBltBufferToVideo);
  blits++; return fail_blt ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static VOID EFIAPI reset_system(EFI_RESET_TYPE type, EFI_STATUS status, UINTN size, VOID *data) {
  CHECK(type==EfiResetWarm && status==EFI_SUCCESS && size==0 && data==NULL); resets++;
}

static void initialize(void) {
  if (mCanvas) free(mCanvas);
  mGop=NULL; mCanvas=NULL; mSerial=NULL; mTicks=mKeyCount=mResetDeadline=0;
  mInputAvailable=mInputSeen=mGopDrawn=mWatchdogDisabled=mTimerReady=mFault=FALSE;
  no_gop=no_input=fail_watchdog=fail_timer=fail_blt=fail_wait=0;
  step=ticks=keys=resets=blits=0; stop_step=0; log_length=0; log_text[0]=0;
  memset(&services,0,sizeof(services)); memset(&system_table,0,sizeof(system_table));
  memset(&runtime,0,sizeof(runtime)); memset(&input,0,sizeof(input)); memset(&graphics,0,sizeof(graphics));
  memset(&mode,0,sizeof(mode)); memset(&info,0,sizeof(info));
  services.LocateProtocol=locate; services.HandleProtocol=handle; services.SetWatchdogTimer=watchdog;
  services.CreateEvent=create; services.SetTimer=timer; services.CloseEvent=close_event;
  services.WaitForEvent=wait_event; services.Stall=stall; runtime.ResetSystem=reset_system;
  input.WaitForKey=(EFI_EVENT)(UINTN)2; input.ReadKeyStroke=read_key;
  info.HorizontalResolution=640; info.VerticalResolution=480; mode.Info=&info; graphics.Mode=&mode; graphics.Blt=blt;
  system_table.ConIn=&input; gBS=&services; gRT=&runtime; gST=&system_table;
}
static void run(unsigned event_count, unsigned key_events) {
  stop_step=event_count; keys=key_events;
  if (no_input) system_table.ConIn=NULL;
  if (!setjmp(escape)) {ShengUefiProbeEntry(NULL,&system_table); CHECK(0);}
}
int main(void) {
  EFI_INPUT_KEY key;
  initialize(); run(301,1); CHECK(mTicks==300 && mKeyCount==1 && RunChecksMet());
  CHECK(strstr(log_text,"APP_ENTRY") && strstr(log_text,"GOP_READY") && strstr(log_text,"MENU_READY"));
  CHECK(strstr(log_text,"HOLD_300_TICKS") && strstr(log_text,"RUN_CHECKS_MET"));
  initialize(); run(300,1); CHECK(mTicks==299 && !RunChecksMet());
  initialize(); run(300,0); CHECK(mTicks==300 && !mInputSeen && !RunChecksMet());
  initialize(); run(400,400); CHECK(mTicks==0 && mKeyCount==400 && !RunChecksMet());
  initialize(); no_gop=1; run(301,1); CHECK(mFault && !mGopDrawn && !RunChecksMet());
  initialize(); no_input=1; run(300,0); CHECK(!mInputAvailable && !RunChecksMet());
  initialize(); fail_watchdog=1; run(301,1); CHECK(mFault && !mWatchdogDisabled && !RunChecksMet());
  initialize(); fail_timer=1; run(3,0); CHECK(mFault && !mTimerReady && mTicks==0 && !RunChecksMet());
  initialize(); fail_blt=1; run(3,0); CHECK(mFault && !mGopDrawn && !RunChecksMet());
  initialize(); fail_wait=1; run(3,0); CHECK(mFault && !mTimerReady && !RunChecksMet());
  initialize(); key.ScanCode=0; key.UnicodeChar=L'y'; HandleKey(&key); CHECK(resets==0);
  key.UnicodeChar=L'r'; HandleKey(&key); CHECK(mResetDeadline==10 && resets==0);
  key.UnicodeChar=L'c'; HandleKey(&key); key.UnicodeChar=L'y'; HandleKey(&key); CHECK(resets==0);
  key.UnicodeChar=L'r'; HandleKey(&key); key.UnicodeChar=L'y'; HandleKey(&key); CHECK(resets==1 && mFault);
  puts("PASS: real probe host simulation: duration/input gates, graphics/watchdog/timer/event failures, confirmed reset");
  if (mCanvas) free(mCanvas);
  return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edk2', type=Path, required=True, help='Mu_Basecore checkout with real MdePkg headers')
    parser.add_argument('--cc', default=shutil.which('cc') or shutil.which('clang') or shutil.which('cl'), help='native C compiler (cc/clang or cl.exe)')
    parser.add_argument('--aarch64-cc', help='optional clang for a real-header AARCH64 freestanding compile')
    args = parser.parse_args()
    if not args.cc:
        parser.error('a native C compiler is required; pass --cc')
    edk2 = args.edk2.resolve()
    source = ROOT / 'package/UefiProbe/ShengUefiProbe.c'
    include = edk2 / 'MdePkg/Include'
    if not (include / 'Uefi.h').is_file():
        parser.error('--edk2 must contain MdePkg/Include/Uefi.h')
    native_arch = 'AArch64' if platform.machine().lower() in ('arm64', 'aarch64') else 'X64'
    with tempfile.TemporaryDirectory(prefix='sheng-probe-check-') as name:
        work = Path(name)
        fixture = work / 'probe-host.c'
        fixture.write_text(HARNESS, encoding='utf-8')
        executable = work / ('probe-host.exe' if platform.system() == 'Windows' else 'probe-host')
        includes = [include, include / native_arch, source.parent]
        if Path(args.cc).name.lower() in ('cl', 'cl.exe'):
            command = [args.cc, '/nologo', '/O2', '/W3', '/D_CRT_SECURE_NO_WARNINGS',
                       *[f'/I{path}' for path in includes], str(fixture), f'/Fe{executable}', f'/Fo{work / "probe-host.obj"}']
        else:
            command = [args.cc, '-std=c11', '-O2', '-fshort-wchar', '-Werror', '-Wall', '-Wextra',
                       '-Wno-unused-parameter', '-Wno-missing-field-initializers',
                       *[argument for path in includes for argument in ('-I', str(path))], str(fixture), '-o', str(executable)]
        subprocess.run(command, check=True, cwd=work)
        subprocess.run([str(executable)], check=True, timeout=45)
        if args.aarch64_cc:
            subprocess.run([args.aarch64_cc, '--target=aarch64-unknown-windows', '-ffreestanding', '-fshort-wchar',
                            '-fno-builtin', '-Werror', '-Wall', '-Wextra', '-Wno-unused-parameter',
                            '-I', str(include), '-I', str(include / 'AArch64'), '-c', str(source),
                            '-o', str(work / 'ShengUefiProbe.obj')], check=True)
            print('PASS: AARCH64 freestanding compilation against real EDK II headers')
    print('Host verification only; firmware build and tablet acceptance remain separate.')


if __name__ == '__main__':
    main()
