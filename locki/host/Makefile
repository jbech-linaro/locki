CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

V			?= y
ifeq (,$(filter $(V),1 y))
VERBOSE			:= @
endif

CFLAGS += -Wall
CFLAGS += -I../ta/include \
	  -I../lib/include \
	  -I$(TEEC_EXPORT)/include \
	  -I./include \
	  -I../common

# Add/link other required libraries here
LDADD += -lteec -L$(TEEC_EXPORT)/lib \
	 -llocki -L../lib

BINARY := locki
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	@echo "  LD      $(notdir $@)"
	$(VERBOSE)$(CC) -o $@ $^ $(LDADD)

.PHONY: locki-clean
locki-clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	@echo "  CC      $(notdir $<)"
	$(VERBOSE)$(CC) $(CFLAGS) -c $< -o $@
