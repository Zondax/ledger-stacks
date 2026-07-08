/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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

#include <hexutils.h>
#include <json/json.h>
#include <parser_txdef.h>

#include <fstream>
#include <iostream>

#include "app_mode.h"
#include "gmock/gmock.h"
#include "parser.h"
#include "utils/common.h"

using ::testing::TestWithParam;

typedef struct {
    uint64_t index;
    std::string name;
    std::string blob;
    std::vector<std::string> expected;
    std::vector<std::string> expected_expert;
} testcase_t;

class JsonTestsA : public ::testing::TestWithParam<testcase_t> {
   public:
    struct PrintToStringParamName {
        template <class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << p.index << "_" << p.name;
            return ss.str();
        }
    };
};

// Retrieve testcases from json file
std::vector<testcase_t> GetJsonTestCases(std::string jsonFile) {
    auto answer = std::vector<testcase_t>();

    Json::CharReaderBuilder builder;
    Json::Value obj;

    std::string fullPathJsonFile = std::string(TESTVECTORS_DIR) + jsonFile;

    std::ifstream inFile(fullPathJsonFile);
    if (!inFile.is_open()) {
        return answer;
    }

    // Retrieve all test cases
    JSONCPP_STRING errs;
    Json::parseFromStream(builder, inFile, &obj, &errs);
    std::cout << "Number of testcases: " << obj.size() << std::endl;

    for (int i = 0; i < obj.size(); i++) {
        auto outputs = std::vector<std::string>();
        for (auto s : obj[i]["output"]) {
            outputs.push_back(s.asString());
        }

        auto outputs_expert = std::vector<std::string>();
        for (auto s : obj[i]["output_expert"]) {
            outputs_expert.push_back(s.asString());
        }

        answer.push_back(testcase_t{obj[i]["index"].asUInt64(), obj[i]["name"].asString(), obj[i]["blob"].asString(),
                                    outputs, outputs_expert});
    }

    return answer;
}

void check_testcase(const testcase_t &tc, bool expert_mode) {
    app_mode_set_expert(expert_mode);
    // Some fixtures carry opaque arguments (tuple, buffer, string-utf8) which parser_parse now
    // gates behind blind signing. These cases exercise rendering, not the gate, so opt in here.
    // The gate itself is covered by BlindSignGate below.
    app_mode_set_blindsign(1);

    parser_context_t ctx;
    parser_error_t err;

    uint8_t buffer[5000];
    MEMZERO(buffer, sizeof(buffer));
    uint16_t bufferLen = parseHexString(buffer, sizeof(buffer), tc.blob.c_str());

    err = parser_parse(&ctx, buffer, bufferLen);
    ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);

    auto output = dumpUI(&ctx, 39, 39);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }
    std::cout << std::endl << std::endl;

    std::vector<std::string> expected = app_mode_expert() ? tc.expected_expert : tc.expected;

    EXPECT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++) {
        if (i < output.size()) {
            EXPECT_THAT(output[i], testing::Eq(expected[i]));
        }
    }
}

INSTANTIATE_TEST_SUITE_P

    (JsonTestCasesCurrentTxVer, JsonTestsA, ::testing::ValuesIn(GetJsonTestCases("testcases.json")),
     JsonTestsA::PrintToStringParamName());

TEST_P(JsonTestsA, CheckUIOutput_CurrentTX_Expert) {
    check_testcase(GetParam(), true);
}
TEST_P(JsonTestsA, CheckUIOutput_CurrentTX) {
    check_testcase(GetParam(), false);
}
///////////////////////////////////////////////////////////////////////////////
// Blind-signing gate
//
// parser_parse() refuses to sign a transaction whose items the device cannot render, unless the
// user has explicitly enabled blind signing. Fixtures below are reused from testcases.json: the
// Contract_call_* cases with tuple/buffer/string-utf8 arguments render placeholders ("is Tuple",
// "is Buffer", ...) and must be gated; everything else renders in full and must not be.
///////////////////////////////////////////////////////////////////////////////

class BlindSignGate : public ::testing::Test {
   protected:
    void SetUp() override {
        app_mode_set_expert(false);
        app_mode_set_blindsign(0);
    }
    void TearDown() override { app_mode_set_blindsign(0); }

    static const testcase_t &testcase(const std::string &name) {
        static const std::vector<testcase_t> cases = GetJsonTestCases("testcases.json");
        for (const auto &c : cases) {
            if (c.name == name) return c;
        }
        ADD_FAILURE() << "missing fixture: " << name;
        std::abort();
    }

    static parser_error_t parse(const std::string &name) {
        parser_context_t ctx;
        uint8_t buffer[5000];
        MEMZERO(buffer, sizeof(buffer));
        const uint16_t bufferLen = parseHexString(buffer, sizeof(buffer), testcase(name).blob.c_str());
        return parser_parse(&ctx, buffer, bufferLen);
    }
};

TEST_F(BlindSignGate, OpaqueArgsRejectedWhenDisabled) {
    app_mode_set_blindsign(0);
    // tuple + buffer + optional-some arguments
    EXPECT_EQ(parse("Contract_call_long_args"), parser_blindsign_mode_required);
    // string-utf8 argument
    EXPECT_EQ(parse("Contract_call_string_args"), parser_blindsign_mode_required);
}

TEST_F(BlindSignGate, OpaqueArgsAllowedWhenEnabled) {
    app_mode_set_blindsign(1);
    EXPECT_EQ(parse("Contract_call_long_args"), parser_ok);
    // The "Accept risk and sign" review must be armed for this transaction.
    EXPECT_TRUE(app_mode_blindsign_required());
}

TEST_F(BlindSignGate, FullyDisplayableTxNotGated) {
    app_mode_set_blindsign(0);
    EXPECT_EQ(parse("Transfer"), parser_ok);
    EXPECT_EQ(parse("Contract_call"), parser_ok);
}

// Regression guard: a user who switches blind signing on must still get the *normal* review for
// transactions the device can render in full -- parser_parse clears the flag via
// app_mode_skip_blindsign_ui(). Without this, every transaction would show the risk warning.
TEST_F(BlindSignGate, FullyDisplayableTxSkipsWarningEvenWhenBlindSignEnabled) {
    app_mode_set_blindsign(1);
    ASSERT_TRUE(app_mode_blindsign_required());
    EXPECT_EQ(parse("Transfer"), parser_ok);
    EXPECT_FALSE(app_mode_blindsign_required());
}

// A SIP-10 transfer renders its memo through render_memo_value, which unwraps Some(..). Its
// arguments go through that renderer whether or not the base items are hidden, so neither variant
// is blind -- gating these would have broken sBTC transfers for every user.
TEST_F(BlindSignGate, Sip10TransferWithMemoNotGated) {
    app_mode_set_blindsign(0);
    EXPECT_EQ(parse("SIP10_contract"), parser_ok);
    EXPECT_EQ(parse("SIP10_contract_hidden_post_condition"), parser_ok);
    EXPECT_EQ(parse("SIP10_contract_shown_post_condition"), parser_ok);
}
