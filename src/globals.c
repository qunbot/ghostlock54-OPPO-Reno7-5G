#include "common.h"

/* globals.c - 全局状态定义（内核地址、原子变量、模式开关） */


struct timespec t_start;
uint64_t runtime_text;
uint64_t k_init_task;
uint64_t k_selinux_state;
uint64_t k_write_value;
uint64_t k_fake_lock;
uint64_t k_fake_lock2;
uint64_t k_ghost_task;
uint64_t k_current_task;
uint64_t k_current_cred;
uint64_t k_y_task;
uint64_t k_waiter;
int __orig_stdout = -1;
pid_t process_pid;
atomic_uintptr_t stamp_parent, stamp_value, stamp_lock;
atomic_int stamp_done, stamp_status;
int pi1, pi2, cond;
atomic_int y_locked_l2, x_locked_l1, y_parking, x_blocking;
atomic_int y_done, y_cleanup, x_done, y_tid;
atomic_int y_task_ready;
atomic_int respray_ready, respray_done;
atomic_uintptr_t respray_parent, respray_value, respray_lock;
unsigned fake_lock_index;
int y_leak_only;
char g_module_path[256] = "/data/local/tmp/kernelsu.ko";
int g_leak_only;
int g_shell_mode;
int g_force_release;
int g_permissive_only;
char g_shell_path[256] = "/system/bin/sh";
