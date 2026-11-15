/* The existing renderer expects Darwin arm64 variadic arguments on the stack.
 * A none-elf C variadic call would instead pass the message pointer in x1.
 * Only this nonreturning veneer calls panic; no C variadic functions are used.
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
.section .text.root_state_panic,"ax",%progbits
.global root_state_panic
.type root_state_panic, %function
root_state_panic:
  sub sp, sp, #16
  str x0, [sp]
  adr x0, .Lformat
  b kernel_panic
.Lformat:
  .asciz "%s"
.size root_state_panic, . - root_state_panic
