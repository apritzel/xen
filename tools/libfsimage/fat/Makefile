XEN_ROOT = $(CURDIR)/../../..

LIB_SRCS-y = fsys_fat.c

FS = fat

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install

.PHONY: uninstall
uninstall: fs-uninstall

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
