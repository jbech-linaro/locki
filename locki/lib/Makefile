CC			?= $(CROSS_COMPILE)gcc
LD			?= $(CROSS_COMPILE)ld
AR			?= $(CROSS_COMPILE)ar
NM			?= $(CROSS_COMPILE)nm
OBJCOPY			?= $(CROSS_COMPILE)objcopy
OBJDUMP			?= $(CROSS_COMPILE)objdump
READELF			?= $(CROSS_COMPILE)readelf

# Paths
OUT_DIR			?= $(CURDIR)
OBJS_PATH		?= $(OUT_DIR)
SRC_PATH		?= $(CURDIR)

MAJOR_VERSION		:= 0
MINOR_VERSION		:= 1
PATCH_VERSION		:= 0
LIB_NAME		:= $(OBJS_PATH)/liblocki.so
LIB_MAJOR		:= $(LIB_NAME).$(MAJOR_VERSION)
LIB_MAJ_MIN		:= $(LIB_NAME).$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_P		:= $(LIB_NAME).$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)

CFG_ENABLE_STRICT	?= n

V			?= n
ifeq (,$(filter $(V),1 y))
VERBOSE			:= @
endif

SRC_PATH		?= $(CURDIR)
SRC			= locki.c \
			  ../common/common.c


# Create a list of objects containing the full path
OBJS		:= $(patsubst %.c,$(OBJS_PATH)/%.o, $(SRC))

# This is just a way to make sure folders in out exists.
OBJDIRS		:= $(dir $(OBJS))
DUMMY		:= $(shell mkdir --parents $(OBJDIRS))

################################################################################
# CFLAGS
################################################################################
CFLAGS := -Wbad-function-cast -Wcast-align \
	  -Werror-implicit-function-declaration -Wextra -Wfloat-equal \
	  -Wformat=2 -Wformat-nonliteral -Wformat-security -Winit-self \
	  -Wmissing-declarations -Wmissing-format-attribute \
	  -Wmissing-include-dirs -Wmissing-noreturn -Wmissing-prototypes \
	  -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes \
	  -Wswitch-default -Wunsafe-loop-optimizations -Wwrite-strings

ifeq ($(CFG_ENABLE_STRICT),y)
CFLAGS += -Werror -Wall
endif

CFLAGS += -fPIC
CFLAGS += -I./include \
	  -I../ta/include \
	  -I../common

################################################################################
# LDFLAGS
################################################################################
LDFLAGS := -lteec -L$(TEEC_EXPORT)/lib
################################################################################
# targets
################################################################################
.PHONY: all
all: $(LIB_NAME)

$(LIB_NAME): $(OBJS)
	@echo "  LD      $(notdir $@)"
	$(VERBOSE)$(CC) $(LDFLAGS) -shared -o $@ $+


$(OBJS_PATH)/%.o: $(SRC_PATH)/%.c
	@echo "  CC      $(notdir $<)"
	$(VERBOSE)$(CC) $(CFLAGS) -c $< -o $@


.PHONY: clean
clean:
	rm -f $(OBJS) $(LIB_NAME)
