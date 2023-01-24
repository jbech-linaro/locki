export V ?= 0

HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

################################################################################
# Overall targets
################################################################################
.PHONY: all
all: ta lib tests host

################################################################################
# Host tools
################################################################################
.PHONY: host
host: lib
	@echo "Building host tools"
	@$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables

.PHONY: host-clean
host-clean:
	@$(MAKE) -C host clean

################################################################################
# Linux user space library
################################################################################
.PHONY: lib
lib:
	@echo "Building $@"
	@$(MAKE) -C lib CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables

.PHONY: lib-clean
lib-clean:
	@$(MAKE) -C lib clean

################################################################################
# Trusted Appplication
################################################################################
.PHONY: ta
ta: 
	@echo "Building TA"
	@$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""

.PHONY: ta-clean
ta-clean:
	@$(MAKE) -C ta clean

################################################################################
# Tests
################################################################################
.PHONY: tests
tests:
	@echo "Building Locki tests"
	@$(MAKE) -C test CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables

.PHONY: tests-clean
tests-clean:
	@$(MAKE) -C test clean

################################################################################
# Generic clean
################################################################################
.PHONY: clean
clean: ta-clean lib-clean tests-clean
