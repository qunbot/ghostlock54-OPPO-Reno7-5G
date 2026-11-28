#include "common.h"

/* ksu.c - 内嵌 kernelsu.ko 的释放（-f 覆盖） */


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
