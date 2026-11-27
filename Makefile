# Build kernelsu.ko and ghostlock54 (single file, ko embedded)
#
# Sources live in src/ (src/*.c compiled into objects, linked with the embedded ko):
#   src/common.h        - shared declarations
#   src/globals.c       - global state
#   src/util.c          - logging/timers/helpers
#   src/leak.c          - KASLR/task/cred/selinux leaks
#   src/futex.c         - futex PI primitive + threads + write_value
#   src/ksu.c           - embedded kernelsu.ko / kernelsu.sh release
#   src/main.c          - CLI + exploit orchestration
#
# Artifacts (no build/ dir):
#   kernelsu/src/kernel/kernelsu.ko           - module build output (with debug info)
#   kernelsu/src/kernel/kernelsu.stripped.ko  - stripped copy embedded into ghostlock54
#   kernelsu/src/kernel/kernelsu_ko.o         - blob object linked into the binary
#
#   make                 # build module + ghostlock54
#   make STRIP=0         # keep debug info in the embedded ko (bigger binary)
#   make module          # build module only
#   make clean

KERNEL_DIR  ?= kernel
MODULE_SH   := kernelsu/build.sh
KO          := kernelsu/src/kernel/kernelsu.ko
KO_STRIP    := kernelsu/src/kernel/kernelsu.stripped.ko
KO_OBJ      := kernelsu/src/kernel/kernelsu_ko.o
BIN         := ghostlock54
SRC_DIR     := src
SRCS        := $(wildcard $(SRC_DIR)/*.c)
OBJS        := $(SRCS:.c=.o)
HDRS        := $(wildcard $(SRC_DIR)/*.h)
CC          ?= clang
CFLAGS      ?= -O2 -pthread
STRIP       ?= 1

.PHONY: all module clean

all: module $(BIN)

module:
	KERNEL_DIR=$(KERNEL_DIR) sh $(MODULE_SH)
	@echo "[make] module -> $(KO)"

$(BIN): $(OBJS) module $(HDRS)
	@if [ "$(STRIP)" = "1" ]; then \
	  rm -f $(KO_STRIP); \
	  llvm-strip --strip-debug -o $(KO_STRIP) $(KO); \
	else \
	  ln -sfn $(CURDIR)/$(KO) $(KO_STRIP); \
	fi
	@echo "[make] embedded ko: $$(stat -Lc %s $(KO_STRIP)) bytes"
	( cd $(dir $(KO_STRIP)) && llvm-objcopy -I binary -O elf64-littleaarch64 -B aarch64 \
	  --redefine-sym _binary_kernelsu_stripped_ko_start=_binary_kernelsu_ko_start \
	  --redefine-sym _binary_kernelsu_stripped_ko_end=_binary_kernelsu_ko_end \
	  --redefine-sym _binary_kernelsu_stripped_ko_size=_binary_kernelsu_ko_size \
	  $(notdir $(KO_STRIP)) $(notdir $(KO_OBJ)) )
	$(CC) $(CFLAGS) $(OBJS) $(KO_OBJ) -o $(BIN)
	@echo "[make] built: $(BIN) ($$(stat -c %s $(BIN)) bytes)"

clean:
	@rm -f $(BIN) $(KO) $(KO_STRIP) $(KO_OBJ) $(OBJS)
	@find kernelsu/src/kernel -type f \( -name '*.o' -o -name '.*.cmd' -o -name '.*.d' \
	  -o -name '*.o.tmp' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' \) -delete
	@rm -f kernelsu/src/kernel/modules.order kernelsu/src/kernel/Module.symvers
	@rm -rf kernelsu/src/kernel/.tmp_versions kernelsu/src/kernel/.tmp_*
	@echo "[make] clean done"
