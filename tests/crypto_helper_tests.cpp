/*******************************************************************************
 *   (c) 2018 - 2026 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <cstdint>
#include <string>
#include <vector>

#include "crypto_helper.h"
#include "gmock/gmock.h"

namespace {

std::string toHex(const uint8_t *data, size_t len) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

std::string sha256Hex(const std::vector<uint8_t> &input) {
    uint8_t digest[CX_SHA256_SIZE];
    EXPECT_EQ(crypto_sha256_one_shot(digest, sizeof(digest), input.data(), (uint32_t)input.size()), zxerr_ok);
    return toHex(digest, sizeof(digest));
}

}  // namespace

// The length carried a uint16_t all the way down to the hasher, so anything past 65535 bytes was
// hashed modulo 64 KiB -- at exactly 64 KiB, not one byte of the input was hashed. Every target
// but Nano S buffers 85 KiB, and this digest is what a SIP-018 structured message signs, so the
// device could return a signature valid over a prefix of the message it was handed.
TEST(CryptoHelper, HashesInputsLargerThan64KiB) {
    // sha256("A" * 70000)
    EXPECT_EQ(sha256Hex(std::vector<uint8_t>(70000, 'A')),
              "b80935d45c7fcb544ad1b841005e50e452239aef65d3e0b6c07976a50f356c69");

    // What the truncating version produced for the same input: sha256("A" * (70000 - 65536)).
    EXPECT_NE(sha256Hex(std::vector<uint8_t>(70000, 'A')),
              "70a296ba0a8c2aaaa714f898080f7f3c0748e48fe3404f6b1dd3c3f6ddf053bf");

    // The old boundary case, where the truncated length was zero.
    EXPECT_EQ(sha256Hex(std::vector<uint8_t>(65536, 'A')),
              "156c38442089c1323d3e3ba549a6ac24341c47e8b6367bec4740c9b8c865826e");
}

TEST(CryptoHelper, RejectsAnUndersizedOutputBuffer) {
    const std::vector<uint8_t> input(32, 'A');
    uint8_t digest[CX_SHA256_SIZE];
    EXPECT_EQ(crypto_sha256_one_shot(digest, CX_SHA256_SIZE - 1, input.data(), (uint32_t)input.size()),
              zxerr_invalid_crypto_settings);
    EXPECT_EQ(crypto_sha256_one_shot(nullptr, sizeof(digest), input.data(), (uint32_t)input.size()),
              zxerr_invalid_crypto_settings);
}
