#*******************************************************************************
#*   (c) 2018 - 2025 Zondax AG
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
cmake_minimum_required(VERSION 3.28)
include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.26.1.tar.gz"
    SHA1 "e41ac7a18c49b35ebac99ff2b5244317b2638a65"
    LOCAL
)

if(CMAKE_GENERATOR MATCHES "Ninja")
        message(FATAL_ERROR "This project does not support the Ninja generator. "
                            "Please use Unix Makefiles or another supported generator. "
                            "This error is typical in CLion. In this case, switch to generator Unix Makefiles.")
endif()

########################################################

project(ledger-stacks VERSION 0.0.0)

set(CMAKE_CXX_STANDARD 17)
cmake_policy(SET CMP0025 NEW)
cmake_policy(SET CMP0144 NEW)

set(HUNTER_STATUS_DEBUG ON)
set(HUNTER_TLS_VERIFY OFF)

enable_testing()

option(ENABLE_COVERAGE "Build with source code coverage instrumentation" OFF)
option(ENABLE_SANITIZERS "Build with ASAN and UBSAN" OFF)

string(APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -g")
string(APPEND CMAKE_CXX_FLAGS " -fno-omit-frame-pointer -g")
string(APPEND CMAKE_LINKER_FLAGS " -fno-omit-frame-pointer -g")

hunter_add_package(fmt)
find_package(fmt CONFIG REQUIRED)

hunter_add_package(jsoncpp)
find_package(jsoncpp CONFIG REQUIRED)

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

if(ENABLE_COVERAGE)
    string(APPEND CMAKE_C_FLAGS " -fprofile-instr-generate -fcoverage-mapping")
    string(APPEND CMAKE_CXX_FLAGS " -fprofile-instr-generate -fcoverage-mapping")
    string(APPEND CMAKE_LINKER_FLAGS " -fprofile-instr-generate -fcoverage-mapping")
endif()

if(ENABLE_SANITIZERS)
    string(APPEND CMAKE_C_FLAGS " -fsanitize=address,undefined -fsanitize-recover=address,undefined")
    string(APPEND CMAKE_CXX_FLAGS " -fsanitize=address,undefined -fsanitize-recover=address,undefined")
    string(APPEND CMAKE_LINKER_FLAGS " -fsanitize=address,undefined -fsanitize-recover=address,undefined")
endif()

set (RETRIEVE_MAJOR_CMD
        "cat ${CMAKE_CURRENT_SOURCE_DIR}/app/Makefile.version | grep APPVERSION_M | cut -b 14- | tr -d '\n'"
)
set (RETRIEVE_MINOR_CMD
        "cat ${CMAKE_CURRENT_SOURCE_DIR}/app/Makefile.version | grep APPVERSION_N | cut -b 14- | tr -d '\n'"
)
execute_process(
        COMMAND bash "-c" ${RETRIEVE_MAJOR_CMD}
        RESULT_VARIABLE MAJOR_RESULT
        OUTPUT_VARIABLE MAJOR_VERSION
)
execute_process(
        COMMAND bash "-c" ${RETRIEVE_MINOR_CMD}
        RESULT_VARIABLE MINOR_RESULT
        OUTPUT_VARIABLE MINOR_VERSION
)

message(STATUS "LEDGER_MAJOR_VERSION [${MAJOR_RESULT}]: ${MAJOR_VERSION}" )
message(STATUS "LEDGER_MINOR_VERSION [${MINOR_RESULT}]: ${MINOR_VERSION}" )

add_definitions(
    -DLEDGER_MAJOR_VERSION=${MAJOR_VERSION}
    -DLEDGER_MINOR_VERSION=${MINOR_VERSION}
    -DAPP_STANDARD
)

##############################################################
# Rust Library Build

# Define Rust build configuration
set(RUST_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/app/rust)
set(RUST_TARGET_DIR ${RUST_SOURCE_DIR}/target)
set(RUST_LIB_NAME rslib)

# Add custom command to build Rust library
add_custom_command(
    OUTPUT ${RUST_TARGET_DIR}/debug/lib${RUST_LIB_NAME}.a
    COMMAND cargo build --features cpp_test
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
    COMMENT "Building Rust library"
    VERBATIM
)

# Create a custom target for the Rust library
add_custom_target(rust_lib DEPENDS ${RUST_TARGET_DIR}/debug/lib${RUST_LIB_NAME}.a)

# Create an imported library target for the Rust library
add_library(${RUST_LIB_NAME} STATIC IMPORTED)
set_target_properties(${RUST_LIB_NAME} PROPERTIES
    IMPORTED_LOCATION ${RUST_TARGET_DIR}/debug/lib${RUST_LIB_NAME}.a
)
add_dependencies(${RUST_LIB_NAME} rust_lib)

##############################################################
# Static Libraries

file(GLOB_RECURSE BLAKE_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/BLAKE2/ref/blake2b-ref.c
        )

file(GLOB_RECURSE LIB_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/app_mode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/base64.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/base58.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/bech32.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/bignum.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/hexutils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/zxmacros.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/zxformat.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/buffering.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/zxcanary.c
        ####
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common/tx.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/c_api/rust.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/crypto_helper.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/token_info.c
        )

add_library(app_lib STATIC
        ${LIB_SRC}
        ${JSMN_SRC}
        ${BLAKE_SRC}
        )

target_include_directories(app_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        ${CMAKE_CURRENT_SOURCE_DIR}/app/rust/include
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/app/common
        ${CMAKE_CURRENT_SOURCE_DIR}/picohash
        ${CMAKE_CURRENT_SOURCE_DIR}
)

##############################################################
#  Tests
file(GLOB_RECURSE TESTS_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)

add_executable(unittests ${TESTS_SRC})
target_include_directories(unittests PRIVATE
        ${gtest_SOURCE_DIR}/include
        ${gmock_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/app/common
        ${CMAKE_CURRENT_SOURCE_DIR}/picohash
        ${CMAKE_CURRENT_SOURCE_DIR}
        )

target_link_libraries(unittests PRIVATE
        app_lib
        ${RUST_LIB_NAME}
        app_lib
        GTest::gtest_main
        fmt::fmt
        JsonCpp::JsonCpp)

add_compile_definitions(TESTVECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/")
add_test(NAME unittests COMMAND unittests)
set_tests_properties(unittests PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)