/* kernel_offsets.h - 内核符号偏移（固定对应 5.4.254-qgki-gaa96eae94d32）
 *
 * 数据来源：vmlinux.elf（vmlinux-to-elf 产物）
 *   LINK_TEXT 对应链接时 _text，其余为相对 _text 的偏移。
 * 换内核版本时必须同步更新本文件。
 */
#ifndef GHOSTLOCK54_KERNEL_OFFSETS_H
#define GHOSTLOCK54_KERNEL_OFFSETS_H

#include <stdint.h>

#define LINK_TEXT UINT64_C(0xffffffc010080000)
#define OFF_INIT_TASK UINT64_C(0x2ca2800)
#define OFF_INIT_CRED UINT64_C(0x2caf850)
#define OFF_SELINUX_STATE UINT64_C(0x2f07000)
#define OFF_LOG_BUF UINT64_C(0x2f1e0b4)
#define OFF_TASK_STATE UINT64_C(0x593324)
#define OFF_FUTEX_WAIT_REQUEUE_PI UINT64_C(0x358d64)
#define OFF_SEL_READ_ENFORCE UINT64_C(0x70ccec)
#define OFF_KALLSYMS_LOOKUP_NAME UINT64_C(0x368354)

#endif
