export V ?= 0

HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

################################################################################
# Overall targets
################################################################################
.PHONY: all
all: ta

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
