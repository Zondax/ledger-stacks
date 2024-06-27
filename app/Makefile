#*******************************************************************************
#  Ledger App
#  (c) 2018 - 2024 Zondax AG
#  (c) 2017 Ledger
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

DEBUG := 0

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CURDIR)/Makefile.conf

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script
include $(BOLOS_SDK)/Makefile.defines

## Display whether this is a production build or for internal use

ifeq ($(PRODUCTION_BUILD), 1)
    $(info ************ PRODUCTION_BUILD  = [PRODUCTION BUILD])
else
    $(info ************ PRODUCTION_BUILD  = [INTERNAL USE])
endif

DEFINES += PRODUCTION_BUILD=$(PRODUCTION_BUILD)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN = STX
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])

ifeq ($(COIN), STX)
# Main app configuration
DEFINES += APP_STANDARD
APPNAME = "Stacks"
APPPATH = "44'/5757'" --path "5757'" --path "888'/0'" --path "44'/1'"
PATH_APP_LOAD_PARAMS = "44'/5757'" "5757'" "888'/0'" "44'/1'"
else
define error_message

COIN value not supported: [$(COIN)]

endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = --curve secp256k1 $(COMMON_LOAD_PARAMS)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

# Add SDK BLAKE2b
DEFINES += HAVE_HASH HAVE_BLAKE2
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

# Configure minimun stack size
ifeq ($(TARGET_NAME),TARGET_NANOS)
	APP_STACK_MIN_SIZE := 1752
else
	APP_STACK_MIN_SIZE := 2000
endif

# Enable app features depending on the target device
ifeq ($(TARGET_NAME), TARGET_NANOS)
RUST_TARGET := thumbv6m-none-eabi
endif

ifeq ($(TARGET_NAME), TARGET_NANOX)
RUST_TARGET := thumbv6m-none-eabi
endif

ifeq ($(TARGET_NAME), TARGET_NANOS2)
RUST_TARGET := thumbv6m-none-eabi
endif

ifeq ($(TARGET_NAME), TARGET_STAX)
RUST_TARGET := thumbv6m-none-eabi
DEFINES += ICONGLYPH=C_icon_stax_64
DEFINES += ICONBITMAP=C_icon_stax_64
DEFINES += ICONGLYPH_SMALL=C_icon_stax_32
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform
INCLUDES_PATH += $(CURDIR)/src/common/

CC := $(CLANGPATH)clang

ifeq ($(DEBUG), 1)
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter -g
else
CFLAGS += -O3 -Os -Wno-unknown-pragmas -Wno-unused-parameter
endif

CFLAGS += -DAPPVERSION_M=$(APPVERSION_M) -DAPPVERSION_N=$(APPVERSION_N) -DAPPVERSION_P=$(APPVERSION_P)

AS := $(GCCPATH)arm-none-eabi-gcc
AFLAGS +=

LD := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -z muldefs
LDLIBS += -lm -lgcc -lc
LDLIBS += -L$(MY_DIR)rust/target/$(RUST_TARGET)/release -lrslib

APP_SOURCE_PATH += $(MY_DIR)/rust/include
APP_SOURCE_PATH += $(MY_DIR)/../deps/sha512

APP_SOURCE_PATH += $(CURDIR)/rust/include
APP_CUSTOM_LINK_DEPENDENCIES := rust

.PHONY: rust
rust:
	cd rust && RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" TARGET_NAME=$(TARGET_NAME) \
	cargo build --release --target $(RUST_TARGET)

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.side_loading

include $(BOLOS_SDK)/Makefile.rules


dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN STX

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version

