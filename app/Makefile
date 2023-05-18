#******************************************************************************
#   Ledger App
#   (c) 2018-2021 Zondax GmbH
#   (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))


all: bin/app.elf
	@echo "#!/usr/bin/env bash" > $(OUTPUT_INSTALLER)
	@echo "APPNAME=\"${APPNAME}\"" >> $(OUTPUT_INSTALLER)
	@echo "APPVERSION=\"${APPVERSION}\"" >> $(OUTPUT_INSTALLER)
	@echo "APPPATH=\""${APPPATH}"\"" >> $(OUTPUT_INSTALLER)
	@echo "LOAD_PARAMS=($$(echo "${APP_LOAD_PARAMS_INSTALLER}" | sed -e "s|"${APPNAME}"|\""${APPNAME}"\"|" | sed "s/\\\'//g"))" >> $(OUTPUT_INSTALLER)
	@echo "DELETE_PARAMS=($$(echo "${COMMON_DELETE_PARAMS}" | sed -e "s|"${APPNAME}"|\""${APPNAME}"\"|" ))" >> $(OUTPUT_INSTALLER)
	@echo "APPHEX=\"" >> $(OUTPUT_INSTALLER)
	@cat $(CURDIR)/bin/app.hex >> $(OUTPUT_INSTALLER)
	@echo "\"" >> $(OUTPUT_INSTALLER)
	@cat $(CURDIR)/../deps/ledger-zxlib/scripts/template.sh >> $(OUTPUT_INSTALLER)
	@chmod +x $(OUTPUT_INSTALLER)
	@cp $(CURDIR)/bin/* $(CURDIR)/output
	@cp $(CURDIR)/output/app.elf ${OUTPUT_ELF}
	@rm $(CURDIR)/output/app.elf

include $(BOLOS_SDK)/Makefile.defines

$(info ************ TARGET_NAME  = [$(TARGET_NAME)])

ifeq ($(APP_TESTING),1)
DEFINES += APP_TESTING
DEFINES += ZEMU_LOGGING
endif

ifndef COIN
COIN=STX
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])

ifeq ($(COIN),STX)
# Main app configuration
DEFINES += APP_STANDARD
APPNAME = "Stacks"
APPPATH = "44'/5757'" --path "5757'" --path "888'/0'"
APPPATH_INSTALLER = "44'/5757'" --path 5757\' --path "888'/0'"

else ifeq ($(COIN),STX_variant1)
else
define error_message
COIN value not supported: [$(COIN)]
endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = --curve secp256k1 $(COMMON_LOAD_PARAMS) --path ${APPPATH} --path "44'/1'"
APP_LOAD_PARAMS_INSTALLER = --curve secp256k1 $(COMMON_LOAD_PARAMS) --path ${APPPATH_INSTALLER} --path "44'/1'"

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices
RUST_TARGET := thumbv6m-none-eabi

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform

LDFLAGS  += -z muldefs
LDLIBS   += -Lrust/target/thumbv6m-none-eabi/release -lrslib
APP_SOURCE_PATH += $(MY_DIR)/rust/include
APP_SOURCE_PATH += $(MY_DIR)/../deps/sha512

APP_CUSTOM_LINK_DEPENDENCIES = rust

.PHONY: rust
rust:
	cd rust && RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" cargo build --target $(RUST_TARGET) --release

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

# load, delete and listvariants are provided to comply with Ledger requirements
.PHONY: load
load:
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

.PHONY: delete
delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: listvariants
listvariants:
	@echo VARIANTS COIN STX

.PHONY: version
version:
	@echo "v$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)" > app.version

.PHONY: rust_tests
rust_tests:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo test

