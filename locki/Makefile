export V ?= 0

HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

################################################################################
# Overall targets
################################################################################
.PHONY: all
all: ta lib

################################################################################
# Linux user space library
################################################################################
.PHONY: lib
lib:
	@echo "Building $@"
	@$(MAKE) -C lib CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables --silent

################################################################################
# Trusted Appplication
################################################################################
.PHONY: ta
ta: 
	@echo "Building TA"
	@$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS="" --silent

.PHONY: ta-clean
ta-clean:
	@$(MAKE) -C ta clean

################################################################################
# Generic clean
################################################################################
.PHONY: clean
clean: ta-clean
