/** Host-only mocks for the real ShengKernelProbe application. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#undef NULL
#include <Uefi.h>

static CONST CHAR16 *mTestArgs;
// Native AARCH64 hosts run at EL0 and cannot read CurrentEL. The separate
// freestanding compile below keeps the firmware instruction enabled.
#define SHENG_KERNEL_PROBE_HOST_TEST 1
#include "ShengKernelProbe.c"

EFI_BOOT_SERVICES *gBS;
EFI_SYSTEM_TABLE *gST;
EFI_GUID gEfiFileInfoGuid = {1};
EFI_GUID gEfiBlockIoProtocolGuid = {2};
EFI_GUID gEfiSimpleFileSystemProtocolGuid = {3};
EFI_GUID gUniXNULoaderProtocolGuid = {4};

static EFI_BOOT_SERVICES services;
static EFI_SYSTEM_TABLE system_table;
static EFI_SIMPLE_TEXT_INPUT_PROTOCOL input;
static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL fs;
static EFI_BLOCK_IO_PROTOCOL block;
static EFI_BLOCK_IO_MEDIA media;
static EFI_FILE_PROTOCOL root, files[PROBE_FILE_COUNT];
static UNIXNU_LOADER_PROTOCOL loader;
static SHENG_KERNEL_DISK_DIAGNOSTIC diagnostic;
static CONST UINT8 seed[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static CONST CHAR16 safe_args[] = L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1";
static unsigned allocations, frees, opened, closed, boot_calls, watchdog_calls;
static unsigned allocation_calls, fail_allocation, read_calls, read_mode, fail_file;
static UINTN position, partial_bytes;
static UINT64 seed_size;
static EFI_STATUS open_volume_status, open_status, get_info_status, read_status;
static EFI_STATUS diagnostic_status, loader_status, block_status, fs_status;
static int null_diagnostic, null_loader, no_input, fail_wait, zero_events;
static jmp_buf escape;
static EFI_INPUT_KEY keys[32];
static unsigned key_count, key_index, event_count, stop_events;
static unsigned scenario;
static int draining;

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"check failed: %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)

UINTN EFIAPI StrLen(CONST CHAR16 *s) { UINTN n=0; while(s[n]) n++; return n; }
INTN EFIAPI StrnCmp(CONST CHAR16 *a, CONST CHAR16 *b, UINTN n) {
  UINTN i; for(i=0;i<n;i++) { if(a[i]!=b[i]) return a[i]>b[i] ? 1 : -1; if(!a[i]) break; } return 0;
}
VOID *EFIAPI CopyMem(VOID *d, CONST VOID *s, UINTN n) { return memcpy(d,s,(size_t)n); }
VOID *EFIAPI ZeroMem(VOID *d, UINTN n) { return memset(d,0,(size_t)n); }
VOID *EFIAPI AllocatePool(UINTN n) {
  VOID *p; allocation_calls++; if(fail_allocation==allocation_calls) return NULL;
  p=malloc((size_t)n); CHECK(p); allocations++; return p;
}
VOID EFIAPI FreePool(VOID *p) { CHECK(p && frees<allocations); frees++; free(p); }
UINTN EFIAPI Print(CONST CHAR16 *format, ...) { (void)format; return 0; }

static EFI_STATUS EFIAPI locate(EFI_GUID *guid, VOID *registration, VOID **out) {
  (void)registration; *out=NULL;
  if(guid==&mDiagnosticGuid) { if(!null_diagnostic) *out=&diagnostic; return diagnostic_status; }
  if(guid==&gUniXNULoaderProtocolGuid) { if(!null_loader) *out=&loader; return loader_status; }
  return EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI handles(EFI_LOCATE_SEARCH_TYPE type, EFI_GUID *guid, VOID *key, UINTN *count, EFI_HANDLE **out) {
  (void)key; CHECK(type==ByProtocol && guid==&gEfiSimpleFileSystemProtocolGuid);
  *count=1; *out=AllocatePool(sizeof(**out)); CHECK(*out); **out=diagnostic.VolumeHandle; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI handle(EFI_HANDLE h, EFI_GUID *guid, VOID **out) {
  CHECK(h==diagnostic.VolumeHandle); *out=NULL;
  if(guid==&gEfiBlockIoProtocolGuid) { *out=&block; return block_status; }
  if(guid==&gEfiSimpleFileSystemProtocolGuid) { *out=&fs; return fs_status; }
  return EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI close_file(EFI_FILE_PROTOCOL *self) { (void)self; closed++; return EFI_SUCCESS; }
static EFI_STATUS EFIAPI volume(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *self, EFI_FILE_PROTOCOL **out) {
  CHECK(self==&fs); *out=NULL; if(EFI_ERROR(open_volume_status)) return open_volume_status;
  *out=&root; opened++; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI open_file(EFI_FILE_PROTOCOL *self, EFI_FILE_PROTOCOL **out, CHAR16 *path, UINT64 mode, UINT64 attributes) {
  UINTN i; CHECK(self==&root && mode==EFI_FILE_MODE_READ && attributes==0); *out=NULL;
  if(EFI_ERROR(open_status)) return open_status;
  for(i=0;i<PROBE_FILE_COUNT;i++) if(StrnCmp(path,mFiles[i].Path,StrLen(path)+1)==0) {
    if(fail_file==i+1) return EFI_NOT_FOUND;
    *out=&files[i]; opened++; position=0; return EFI_SUCCESS;
  }
  CHECK(0); return EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI info(EFI_FILE_PROTOCOL *self, EFI_GUID *guid, UINTN *size, VOID *data) {
  EFI_FILE_INFO *f; CHECK(guid==&gEfiFileInfoGuid);
  if(EFI_ERROR(get_info_status)) return get_info_status;
  if(!data) { *size=SIZE_OF_EFI_FILE_INFO; return EFI_BUFFER_TOO_SMALL; }
  CHECK(*size>=SIZE_OF_EFI_FILE_INFO); memset(data,0,(size_t)*size); f=data;
  f->FileSize=self==&files[PROBE_FILE_COUNT-1] ? seed_size : 100; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI read_file(EFI_FILE_PROTOCOL *self, UINTN *size, VOID *data) {
  UINTN n=*size; CHECK(self==&files[PROBE_FILE_COUNT-1]); read_calls++;
  if(EFI_ERROR(read_status)) return read_status;
  if(read_mode==1) { *size=0; return EFI_SUCCESS; }
  if(read_mode==2) { (*size)++; return EFI_SUCCESS; }
  if(n>partial_bytes) n=partial_bytes;
  if(n>sizeof(seed)-position) n=sizeof(seed)-position;
  memcpy(data,seed+position,(size_t)n); position+=n; *size=n; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI boot(UNIXNU_LOADER_PROTOCOL *self, CONST UNIXNU_LOADER_BOOT_REQUEST *request) {
  CHECK(self==&loader && request); CHECK(request->Volume==diagnostic.VolumeHandle);
  CHECK(request->KernelPath==mFiles[0].Path && request->BootArgs==mTestArgs);
  CHECK(request->RamdiskSize==sizeof(seed) && memcmp(request->Ramdisk,seed,sizeof(seed))==0);
  CHECK(request->DeviceTree==NULL && request->DeviceTreeSize==0);
  CHECK(request->Kexts==NULL && request->KextCount==0); boot_calls++; return EFI_ACCESS_DENIED;
}
static EFI_STATUS EFIAPI watchdog(UINTN timeout, UINT64 code, UINTN size, CHAR16 *data) {
  CHECK(timeout==0 && code==0 && size==0 && data==NULL); watchdog_calls++; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI wait_event(UINTN count, EFI_EVENT *events, UINTN *index) {
  CHECK(count==1 && events==&input.WaitForKey); draining=0;
  if(event_count++>=stop_events) longjmp(escape,1);
  if(fail_wait) return EFI_DEVICE_ERROR;
  *index=0; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI stall(UINTN microseconds) {
  CHECK(microseconds==100000 || microseconds==1000000);
  if(event_count++>=stop_events) longjmp(escape,1); return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI read_key(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *self, EFI_INPUT_KEY *key) {
  CHECK(self==&input);
  if(draining || zero_events || key_index>=key_count) return EFI_NOT_READY;
  *key=keys[key_index++]; return EFI_SUCCESS;
}

static void initialize(void) {
  UINTN i; CHECK(allocations==frees); CHECK(opened==closed);
  scenario++;
  memset(&services,0,sizeof(services)); memset(&system_table,0,sizeof(system_table));
  memset(&input,0,sizeof(input)); memset(&fs,0,sizeof(fs)); memset(&block,0,sizeof(block));
  memset(&media,0,sizeof(media)); memset(&root,0,sizeof(root)); memset(files,0,sizeof(files));
  memset(&diagnostic,0,sizeof(diagnostic)); memset(&mDiagnostic,0,sizeof(mDiagnostic));
  allocations=frees=opened=closed=boot_calls=watchdog_calls=0;
  allocation_calls=fail_allocation=read_calls=read_mode=fail_file=0;
  null_diagnostic=null_loader=no_input=fail_wait=zero_events=0;
  key_count=key_index=event_count=stop_events=0; draining=1;
  position=0; partial_bytes=3; seed_size=sizeof(seed); mTestArgs=safe_args;
  open_volume_status=open_status=get_info_status=read_status=EFI_SUCCESS;
  diagnostic_status=loader_status=block_status=fs_status=EFI_SUCCESS;
  mVolumeStatus=mLoaderStatus=mLastBootStatus=EFI_NOT_READY; mDiagnosticStatus=EFI_NOT_READY;
  mPage=mReadOnlyVolumes=0; mConfirming=mConfirmBoot=mBootAttempted=mVerifiedVolume=mArgumentsSafe=FALSE;
  mFileSystem=NULL; mLoader=NULL;
  for(i=0;i<PROBE_FILE_COUNT;i++) { mFiles[i].Status=EFI_NOT_READY; mFiles[i].Bytes=0; files[i].GetInfo=info; files[i].Read=read_file; files[i].Close=close_file; }
  diagnostic.Revision=SHENG_KERNEL_DISK_DIAGNOSTIC_REVISION; diagnostic.State=ShengKernelDiskVolumePublished;
  diagnostic.Flags=SHENG_KERNEL_DISK_FLAG_PUBLISHED|SHENG_KERNEL_DISK_FLAG_VOLUME_SHA_MATCH;
  diagnostic.Status=diagnostic.RangeStatus=EFI_SUCCESS; diagnostic.VolumeHandle=(EFI_HANDLE)(UINTN)123;
  loader.Revision=UNIXNU_LOADER_REVISION; loader.Boot=boot; media.ReadOnly=TRUE; block.Media=&media;
  fs.OpenVolume=volume; root.Open=open_file; root.Close=close_file;
  services.LocateProtocol=locate; services.LocateHandleBuffer=handles; services.HandleProtocol=handle;
  services.SetWatchdogTimer=watchdog; services.WaitForEvent=wait_event; services.Stall=stall;
  input.WaitForKey=(EFI_EVENT)(UINTN)1; input.ReadKeyStroke=read_key;
  system_table.ConIn=&input; gBS=&services; gST=&system_table;
}
static void rejected(void) { Snapshot(); CHECK(!CanBoot()); CHECK(BootFullKernel()==EFI_NOT_READY && boot_calls==0); }
static void ready(void) {
  UINTN i;
  Snapshot();
  if(!CanBoot()) {
    CONST CHAR16 *token, *end;
    UINTN token_length, unit;
    fprintf(stderr,"ready scenario=%u: arguments=%u verified=%u attempted=%u diagnostic=%llx status=%llx range=%llx state=%u flags=%x volume=%p loader=%llx volume_status=%llx\n",
            scenario,(unsigned)mArgumentsSafe,(unsigned)mVerifiedVolume,(unsigned)mBootAttempted,
            (unsigned long long)mDiagnosticStatus,(unsigned long long)mDiagnostic.Status,
            (unsigned long long)mDiagnostic.RangeStatus,(unsigned)mDiagnostic.State,
            (unsigned)mDiagnostic.Flags,mDiagnostic.VolumeHandle,
            (unsigned long long)mLoaderStatus,(unsigned long long)mVolumeStatus);
    for(i=0;i<PROBE_FILE_COUNT;i++) fprintf(stderr,"file[%u]: status=%llx bytes=%llu\n",(unsigned)i,
      (unsigned long long)mFiles[i].Status,(unsigned long long)mFiles[i].Bytes);
    fprintf(stderr,"strings: CHAR16=%u wide_literal_unit=%u safe_units=%u args_length=%llu guard_length=%llu compare=%lld\n",
      (unsigned)sizeof(CHAR16),(unsigned)sizeof(L"x"[0]),(unsigned)(sizeof(safe_args)/sizeof(safe_args[0])),
      (unsigned long long)StrLen(mTestArgs),(unsigned long long)StrLen(L"data-persist"),
      (long long)StrnCmp(mTestArgs,L"data-persist",12));
    fprintf(stderr,"argument code units:");
    for(unit=0;unit<sizeof(safe_args)/sizeof(safe_args[0]);unit++) fprintf(stderr," %04x",(unsigned)mTestArgs[unit]);
    fprintf(stderr,"\n");
    token=mTestArgs;
    for(i=0;i<16 && *token;i++) {
      while(*token==L' ') token++;
      if(!*token) break;
      end=token; while(*end && *end!=L' ' && (UINTN)(end-token)<1000) end++;
      token_length=(UINTN)(end-token);
      fprintf(stderr,"token[%u]: units=%llu forbidden=%u/%u names=%u/%u/%u/%u exact=%u/%u/%u/%u\n",
        (unsigned)i,(unsigned long long)token_length,
        (unsigned)TokenNames(token,token_length,L"data-reset"),(unsigned)TokenNames(token,token_length,L"autoreset"),
        (unsigned)TokenNames(token,token_length,L"data-persist"),(unsigned)TokenNames(token,token_length,L"log"),
        (unsigned)TokenNames(token,token_length,L"native-source-storage"),(unsigned)TokenNames(token,token_length,L"native-ufs-root"),
        (unsigned)TokenIs(token,token_length,L"data-persist=0"),(unsigned)TokenIs(token,token_length,L"log=0"),
        (unsigned)TokenIs(token,token_length,L"native-source-storage=1"),(unsigned)TokenIs(token,token_length,L"native-ufs-root=1"));
      token=end;
    }
  }
  CHECK(CanBoot());
}
static void push(UINT16 scan, CHAR16 ch) { CHECK(key_count<32); keys[key_count].ScanCode=scan; keys[key_count++].UnicodeChar=ch; }
static void run_ui(unsigned steps) {
  stop_events=steps; if(no_input) system_table.ConIn=NULL;
  if(!setjmp(escape)) { ShengKernelProbeEntry(NULL,&system_table); CHECK(0); }
  CHECK(watchdog_calls==1);
}
static void seed_failure(EFI_STATUS expected) {
  CHECK(BootFullKernel()==expected && boot_calls==0 && mBootAttempted); CHECK(allocations==frees && opened==closed);
  CHECK(BootFullKernel()==EFI_NOT_READY);
}
int main(void) {
  UINTN i; static CONST CHAR16 *bad_args[] = {
    L"", L"data-persist=2 log=0 native-source-storage=1 native-ufs-root=1",
    L"data-persist=0 log=1 native-source-storage=1 native-ufs-root=1",
    L"data-persist=0 log=0 native-source-storage=0 native-ufs-root=1",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=0",
    L"data-persist=0 log=0 native-source-storage=1",
    L"data-persist=0 log=0 native-ufs-root=1",
    L"data-persist=0 native-source-storage=1 native-ufs-root=1",
    L"log=0 native-source-storage=1 native-ufs-root=1",
    L"data-persist=0 data-persist=0 log=0 native-source-storage=1 native-ufs-root=1",
    L"data-persist=0 log=0 log=0 native-source-storage=1 native-ufs-root=1",
    L"data-persist=0 log=0 native-source-storage=1 native-source-storage=1 native-ufs-root=1",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1 native-ufs-root=1",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1 data-reset",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1 data-reset=0",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1 autoreset",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1 autoreset=0",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1 foo\tdata-reset=1",
    L"data-persist=0 log=0 native-source-storage=1 native-ufs-root=1 foo\nautoreset=1"
  };
  initialize(); ready(); CHECK(BootFullKernel()==EFI_ACCESS_DENIED && boot_calls==1 && read_calls==6);
  CHECK(BootFullKernel()==EFI_NOT_READY && boot_calls==1 && allocations==frees && opened==closed);
  initialize(); loader.Revision=UNIXNU_LOADER_REVISION_1; ready(); CHECK(BootFullKernel()==EFI_ACCESS_DENIED && boot_calls==1);
  for(i=0;i<sizeof(bad_args)/sizeof(bad_args[0]);i++) { initialize(); mTestArgs=bad_args[i]; rejected(); }
  initialize(); { static CHAR16 long_args[1002]; for(i=0;i<1001;i++) long_args[i]=L'a'; long_args[1001]=0; mTestArgs=long_args; rejected(); }
  initialize(); diagnostic_status=EFI_NOT_FOUND; rejected();
  initialize(); null_diagnostic=1; rejected();
  initialize(); diagnostic.Revision++; rejected();
  initialize(); diagnostic.Status=EFI_DEVICE_ERROR; rejected();
  initialize(); diagnostic.RangeStatus=EFI_ACCESS_DENIED; rejected();
  initialize(); diagnostic.State=ShengKernelDiskVolumeDigestMismatch; rejected();
  initialize(); diagnostic.Flags&=~SHENG_KERNEL_DISK_FLAG_PUBLISHED; rejected();
  initialize(); diagnostic.Flags&=~SHENG_KERNEL_DISK_FLAG_VOLUME_SHA_MATCH; rejected();
  initialize(); diagnostic.VolumeHandle=NULL; rejected();
  initialize(); media.ReadOnly=FALSE; rejected();
  initialize(); block.Media=NULL; rejected();
  initialize(); block_status=EFI_NOT_FOUND; rejected();
  initialize(); fs_status=EFI_NOT_FOUND; rejected();
  initialize(); loader_status=EFI_NOT_FOUND; rejected();
  initialize(); null_loader=1; rejected();
  initialize(); loader.Revision=0; rejected();
  initialize(); loader.Boot=NULL; rejected();
  for(i=1;i<=PROBE_FILE_COUNT;i++) { initialize(); fail_file=(unsigned)i; rejected(); }
  initialize(); seed_size++; rejected();
  initialize(); open_volume_status=EFI_DEVICE_ERROR; rejected();
  initialize(); open_status=EFI_DEVICE_ERROR; rejected();
  initialize(); get_info_status=EFI_DEVICE_ERROR; rejected();
  initialize(); ready(); seed_size++; seed_failure(EFI_BAD_BUFFER_SIZE);
  initialize(); ready(); read_mode=1; seed_failure(EFI_END_OF_FILE);
  initialize(); ready(); read_mode=2; seed_failure(EFI_END_OF_FILE);
  initialize(); ready(); read_status=EFI_DEVICE_ERROR; seed_failure(EFI_DEVICE_ERROR);
  initialize(); ready(); fail_allocation=allocation_calls+1; seed_failure(EFI_OUT_OF_RESOURCES);
  initialize(); ready(); fail_allocation=allocation_calls+2; seed_failure(EFI_OUT_OF_RESOURCES);
  initialize(); ready(); open_volume_status=EFI_DEVICE_ERROR; seed_failure(EFI_DEVICE_ERROR);
  initialize(); ready(); open_status=EFI_DEVICE_ERROR; seed_failure(EFI_DEVICE_ERROR);
  initialize(); ready(); get_info_status=EFI_DEVICE_ERROR; seed_failure(EFI_DEVICE_ERROR);
  // Entry does not return into BDS on Esc or on its recovery page.
  initialize(); push(SCAN_ESC,0); push(SCAN_UP,0); push(0,CHAR_CARRIAGE_RETURN); run_ui(4); CHECK(mPage==4 && boot_calls==0);
  // Opening confirmation defaults Cancel; selecting it never calls the loader.
  initialize(); push(SCAN_UP,0); push(SCAN_UP,0); push(0,CHAR_CARRIAGE_RETURN); push(0,CHAR_CARRIAGE_RETURN); run_ui(4); CHECK(!mConfirming && boot_calls==0);
  initialize(); push(SCAN_UP,0); push(SCAN_UP,0); push(0,CHAR_CARRIAGE_RETURN); push(SCAN_ESC,0); run_ui(4); CHECK(!mConfirming && boot_calls==0);
  initialize(); push(SCAN_UP,0); push(SCAN_UP,0); push(0,CHAR_CARRIAGE_RETURN); push(SCAN_DOWN,0); push(0,CHAR_CARRIAGE_RETURN); push(0,CHAR_CARRIAGE_RETURN); run_ui(6); CHECK(mBootAttempted && boot_calls==1 && mLastBootStatus==EFI_ACCESS_DENIED);
  initialize(); no_input=1; run_ui(3); CHECK(boot_calls==0);
  initialize(); fail_wait=1; run_ui(3); CHECK(boot_calls==0);
  initialize(); zero_events=1; run_ui(3); CHECK(boot_calls==0);
  initialize();
  puts("PASS: real kernel probe host simulation: verified-volume/argument gates, exact partial seed reads, cleanup, one callback, confirmation and persistent recovery display");
  return 0;
}
