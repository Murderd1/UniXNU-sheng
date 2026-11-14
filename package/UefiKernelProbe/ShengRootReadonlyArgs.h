/** Audited handoff whitelist for the existing kernel's UFS root probe 10. */
#ifndef SHENG_ROOT_READONLY_ARGS_H_
#define SHENG_ROOT_READONLY_ARGS_H_

#define SHENG_ROOT_READONLY_ARGS L"-v serial=3 debug=0x14e kt_fixed_zones=120 -no_slto_panic use_contiguous_hint=0 native-source-storage=1 native-ufs-root=1 native-ufs-probe=10 log=0 data-persist=0 wifi=0 dpu=0 dpu-scanout=0 smp=1 armcpu-spi-ipi=1 armcpu-self-ipi=1"

#endif
