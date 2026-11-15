/* Delayed, read-only boot state snapshot for the fixed rootauth3 kernel.
 * Compiled independently of XNU; RootStateProbeSymbols.h is generated from
 * the verified candidate's real N_SECT symbols by patch-sheng-root-state.py.
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned long long u64;
typedef signed long long s64;

#include "RootStateProbeSymbols.h"

extern void kernel_IOSleep (unsigned int milliseconds);
extern __attribute__((noreturn)) void root_state_panic (const char *message);

struct output {
  char *text;
  unsigned used;
};

static void put (struct output *out, char value)
{
  if (out->used < 1023) {
    out->text[out->used++] = value;
  }
}

static void text (struct output *out, const char *value)
{
  while (*value) {
    put (out, *value++);
  }
}

static void number (struct output *out, u64 value, unsigned base)
{
  char digits[24];
  unsigned count = 0;
  do {
    unsigned digit = (unsigned)(value % base);
    digits[count++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
    value /= base;
  } while (value && count < sizeof (digits));
  while (count) {
    put (out, digits[--count]);
  }
}

static void signed_field (struct output *out, const char *label, u64 address)
{
  s64 value = *(volatile const s32 *)address;
  text (out, label);
  if (value < 0) {
    put (out, '-');
    value = -value;
  }
  number (out, (u64)value, 10);
}

static void unsigned_field (struct output *out, const char *label, u64 address, unsigned width)
{
  text (out, label);
  number (out, width == 8 ? *(volatile const u64 *)address : *(volatile const u32 *)address, 10);
}

static void device_field (struct output *out, const char *label, u64 address)
{
  text (out, label);
  number (out, *(volatile const u32 *)address, 16);
}

__attribute__((noreturn, used, section(".text.root_state_entry")))
void root_state_thread (void *argument, int wait_result)
{
  char buffer[1024];
  struct output out = { buffer, 0 };
  unsigned seconds = (unsigned)(u64)argument;
  (void)wait_result;

  // Match the existing statsThread's 32-bit seconds * 1000 semantics.
  kernel_IOSleep (seconds * 1000U);
  text (&out, "ROOT STATE probe13 delay=");
  number (&out, seconds, 10);
  text (&out, "s (sampled, non-atomic)\nroot");
  signed_field (&out, " accepted=", ROOT_ACCEPTED);
  signed_field (&out, " apple=", ROOT_APPLE);
  signed_field (&out, " decision=", ROOT_DECISION);
  signed_field (&out, " ro=", ROOT_READONLY);
  device_field (&out, "\nroot mount=", ROOT_MOUNT_DEVICE);
  device_field (&out, " selected=", ROOT_SELECTED_DEVICE);
  device_field (&out, " rootdev=", ROOT_DEVICE);
  signed_field (&out, "\ncache stage=", CACHE_STAGE);
  signed_field (&out, " status=", CACHE_STATUS);
  signed_field (&out, " mount=", CACHE_MOUNT_STATUS);
  signed_field (&out, " ro=", CACHE_READONLY);
  signed_field (&out, " auth=", CACHE_AUTHORIZED);
  signed_field (&out, " recheck=", CACHE_ROOT_RECHECK);
  signed_field (&out, " union=", CACHE_UNION);
  device_field (&out, "\ncache selected=", CACHE_SELECTED_DEVICE);
  device_field (&out, " mounted=", CACHE_MOUNTED_DEVICE);
  signed_field (&out, "\ndata stage=", DATA_STAGE);
  signed_field (&out, " status=", DATA_STATUS);
  signed_field (&out, " ro=", DATA_READONLY);
  device_field (&out, " dev=", DATA_DEVICE);
  unsigned_field (&out, "\nufs step=", UFS_STEP, 4);
  unsigned_field (&out, " published=", UFS_PUBLISHED, 4);
  unsigned_field (&out, " reads=", UFS_READS, 8);
  unsigned_field (&out, " failures=", UFS_FAILURES, 8);
  unsigned_field (&out, "\nram ready=", RAM_READY, 4);
  unsigned_field (&out, " sparse=", RAM_SPARSE, 4);
  unsigned_field (&out, " reads=", RAM_READS, 8);
  unsigned_field (&out, " writes=", RAM_WRITES, 8);
  unsigned_field (&out, " failures=", RAM_FAILURES, 8);
  unsigned_field (&out, "\nstore writes=", STORE_WRITES, 8);
  unsigned_field (&out, " syncs=", STORE_SYNCS, 8);
  signed_field (&out, "\nnprocs=", PROCESS_COUNT);
  text (&out, "\ncounters: early NotReady untracked");
  buffer[out.used] = 0;
  root_state_panic (buffer);
}
