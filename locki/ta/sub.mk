global-incdirs-y += include
global-incdirs-y += ../common
srcs-y += locki_ta.c
srcs-y += ../common/common.c

# To remove a certain compiler flag, add a line like this
cflags-locki_ta.c-y += -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable
