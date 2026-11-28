#include "common.h"

/* ksu.c - 内嵌 kernelsu.ko / kernelsu.sh 的释放（-f 覆盖） */


/* 取路径的 basename 作为 argv[0]（bash/toybox 等多调用程序依赖它） */
const char *path_basename(const char *p) {
  const char *s = strrchr(p, '/');
  return s ? s + 1 : p;
}
/* ---------------------------------------------- */

/* ---------- 释放内嵌的 kernelsu.ko ---------- */
extern const unsigned char _binary_kernelsu_ko_start[];
extern const unsigned char _binary_kernelsu_ko_end[];

void ksu_release_module(void) {
  const char *path = g_module_path;
  size_t len = (size_t)(_binary_kernelsu_ko_end - _binary_kernelsu_ko_start);
  if (!len) { pr_warning("[KSU] embedded module is empty\n"); return; }

  int existed = 0;
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0 && errno == EEXIST) {
    existed = 1;
    if (!g_force_release) {
      pr_info("[KSU] %s exists, not overwritten (use -f to force)\n", path);
      return;
    }
    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
  }
  if (fd < 0) {
    pr_warning("[KSU] cannot release %s: %s\n", path, strerror(errno));
    return;
  }
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, _binary_kernelsu_ko_start + off, len - off);
    if (n <= 0) {
      close(fd); (void)unlink(path);
      pr_warning("[KSU] write %s failed (partial file removed)\n", path);
      return;
    }
    off += (size_t)n;
  }
  close(fd);
  (void)chmod(path, 0644);
  pr_info("[KSU] %s %s (%zu bytes)\n", existed ? "overwritten" : "created", path, len);
}
/* --------------------------------------- */

/* ---------- 释放 kernelsu.sh ---------- */
const char ksu_script[] =
  "#!/system/bin/sh\n"
  "# kernelsu.sh - released by ghostlock54 (kept unless -f)\n"
  "# Loads KernelSU module. Run inside a root shell (e.g. ghostlock54 -s).\n"
  "KO=\"${1:-/data/local/tmp/kernelsu.ko}\"\n"
  "\n"
  "if [ ! -f \"$KO\" ]; then\n"
  "  echo \"[-] module not found: $KO\" >&2\n"
  "  exit 1\n"
  "fi\n"
  "\n"
  "if grep -q kernelsu /proc/modules 2>/dev/null || [ -d /sys/module/kernelsu ]; then\n"
  "  echo \"[+] kernelsu already loaded\"\n"
  "  exit 0\n"
  "fi\n"
  "\n"
  "KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)\n"
  "echo 1 > /proc/sys/kernel/kptr_restrict 2>/dev/null\n"
  "\n"
  "KLN=$(grep ' T kallsyms_lookup_name$' /proc/kallsyms 2>/dev/null | head -n 1 | cut -d' ' -f1)\n"
  "if [ -n \"$KPTR\" ]; then echo \"$KPTR\" > /proc/sys/kernel/kptr_restrict 2>/dev/null; fi\n"
  "if [ -z \"$KLN\" ]; then\n"
  "  echo \"[-] kallsyms_lookup_name not found (need root)\" >&2\n"
  "  exit 1\n"
  "fi\n"
  "\n"
  "echo \"[*] kln=0x$KLN\"\n"
  "\n"
  "# 直接用 KernelSU Manager 自带的 libksud.so 加载（glob 自动解析安装哈希路径）\n"
  "/data/app/*/me.weishu.kernelsu-*/lib/arm64/libksud.so insmod \"$KO\" kln=0x$KLN level=3\n"
  "RC=$?\n"
  "if [ ! -d /sys/module/kernelsu ]; then\n"
  "  echo \"[*] libksud did not load (rc=$RC), falling back to insmod\"\n"
  "  /system/bin/insmod \"$KO\" kln=0x$KLN level=3\n"
  "  RC=$?\n"
  "fi\n"
  "if [ ! -d /sys/module/kernelsu ]; then\n"
  "  echo \"[-] module load failed (rc=$RC)\" >&2\n"
  "  exit 1\n"
  "fi\n"
  "exit 0\n"
  "\n";

void ksu_release_script(void) {
  const char *path = "/data/local/tmp/kernelsu.sh";
  int existed = 0;
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
  if (fd < 0 && errno == EEXIST) {
    existed = 1;
    if (!g_force_release) {
      pr_info("[KSU] %s exists, not overwritten (use -f to force)\n", path);
      return;
    }
    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC, 0755);
  }
  if (fd < 0) {
    pr_warning("[KSU] cannot release %s: %s\n", path, strerror(errno));
    return;
  }
  size_t len = sizeof(ksu_script) - 1, off = 0;
  while (off < len) {
    ssize_t n = write(fd, ksu_script + off, len - off);
    if (n <= 0) {
      close(fd); (void)unlink(path);
      pr_warning("[KSU] write %s failed (partial file removed)\n", path);
      return;
    }
    off += (size_t)n;
  }
  close(fd);
  (void)chmod(path, 0755);
  pr_info("[KSU] %s %s\n", existed ? "overwritten" : "created", path);
}
/* -------------------------------------- */

