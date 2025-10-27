#*******************************************************************************
#*   (c) 2019 - 2024 Zondax AG
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************

TESTS_JS_PACKAGE = "@zondax/ledger-stacks"
TESTS_JS_DIR = $(CURDIR)/js

ifeq ($(BOLOS_SDK),)
# In this case, there is not predefined SDK and we run dockerized
# When not using the SDK, we override and build the XL complete app

ZXLIB_COMPILE_STAX ?= 1
PRODUCTION_BUILD ?= 1
SKIP_NANOS ?= 1

include $(CURDIR)/deps/ledger-zxlib/dockerized_build.mk

else
default:
	$(MAKE) -C app
%:
	$(info "Calling app Makefile for target $@")
	COIN=$(COIN) PRODUCTION_BUILD=$(PRODUCTION_BUILD) $(MAKE) -C app $@
endif

test_all:
	make clean
	make PRODUCTION_BUILD=1
	make zemu_install
	make zemu_test

prod:
	make PRODUCTION_BUILD=1

rust_fuzz:
	cd app/hfuzz-parser/corpus/ && cargo run
	cd app/hfuzz-parser/ && RUSTFLAGS="--cfg fuzzing_build" cargo hfuzz run transaction app/hfuzz_corpus



