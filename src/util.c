#include "common.h"

/* util.c - 计时、日志上下文、read_enforce()、wait_atomic_ms() */


void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t_start); }
double timer_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t_start.tv_sec) * 1000.0 + (now.tv_nsec - t_start.tv_nsec) / 1e6;
}

int wait_atomic_ms(atomic_int *v, long ms) {
  struct timespec s, n;
  clock_gettime(CLOCK_MONOTONIC, &s);
  for (;;) {
    if (atomic_load(v)) return 1;
    clock_gettime(CLOCK_MONOTONIC, &n);
    long el = (n.tv_sec - s.tv_sec) * 1000L + (n.tv_nsec - s.tv_nsec) / 1000000L;
    if (el > ms) return 0;
    sched_yield();
  }
}

/* 读取 /proc/self/attr/current 并打印 */
void log_context(const char *tag) {
  char buf[256] = {0};
  int f = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
  if (f >= 0) {
    ssize_t n = read(f, buf, sizeof(buf) - 1);
    close(f);
    if (n > 0) buf[n] = 0;
  }
  pr_info("%s: %s\n", tag, buf);
}


int read_enforce(void) {
  char b[4] = {0}; int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (fd < 0) return -1;
  ssize_t n = read(fd, b, sizeof(b)); close(fd);
  return n > 0 ? b[0] - '0' : -1;
}

