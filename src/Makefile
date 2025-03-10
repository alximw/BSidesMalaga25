
OUTPUT = $(abspath ../build)
LIBBPF_SRC := $(abspath dependencies/libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
ARCH ?= arm64
CFLAGS := -g -Wall -D__TARGET_ARCH_$(ARCH)
# gcc toolchain needed to compile libbpf
CC = aarch64-linux-gnu-gcc
LD = aarch64-linux-gnu-ld
CLANG ?= clang
LLC ?= llc

msg = @printf '  %-8s %s%s\n'							\
	      "$(1)"										\
	      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
	      "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory


PROGS:=strace network_monitor evade_root dex_dumper


all: $(PROGS)

.PHONY:
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)

# called if any of these dont exist
$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf (order only dependency to force output/libbpf to exist before running but avoid rebuilding it if it changes)
.PHONY:
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,Making libbpf,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)\
			INCLUDEDIR=. LIBDIR= UAPIDIR=			 \
		    install

# build user_space programs
$(PROGS): %: %_user.c  helper.c $(LIBBPF_OBJ)|$(OUTPUT)/%.bpf.o
	$(call msg, Building user-space loader,$@)
	$(Q)$(CC) $(CFLAGS) -static $^ 					\
		 -Idependencies/libbpf/src/				\
		 -Ldependencies/libelf-aarch64/usr/lib  \
		 -lelf									\
		 -Ldependencies/zlib-1.2.10 			\
		 -lz -o $(OUTPUT)/$@


# build bpf programs
$(OUTPUT)/%.bpf.o: %_kern.c 
	$(call msg, Building BPF programs,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		\
			 -include vmlinux/vmlinux.h    					\
			 -Ivmlinux/										\
			 -Idependencies/libbpf/src						\
			 -Idependencies/libbpf/include/bpf				\
		     -c $^ -o $@


	




