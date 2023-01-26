global-incdirs-y += include
global-incdirs-y += ../common
srcs-y += ta_locki.c
srcs-y += ta_locki_crypto.c
srcs-y += ta_locki_debug.c
srcs-y += ta_locki_keys.c
srcs-y += ta_locki_measure.c
srcs-y += ta_locki_user.c
srcs-y += ta_locki_utils.c
srcs-y += ../common/common.c

# To remove a certain compiler flag, add a line like this
# cflags-ta_locki.c-y += -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable
