/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
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
 ******************************************************************************* */

import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import BlockstackApp from "@zondax/ledger-blockstack";

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const simOptions = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
    ,X11: true
};

jest.setTimeout(15000)

function compareSnapshots(snapshotPrefixTmp, snapshotPrefixGolden, snapshotCount) {
    for (let i = 0; i < snapshotCount; i++) {
        const img1 = Zemu.LoadPng2RGB(`${snapshotPrefixTmp}${i}.png`);
        const img2 = Zemu.LoadPng2RGB(`${snapshotPrefixGolden}${i}.png`);
        expect(img1).toEqual(img2);
    }
}

describe('Basic checks', function () {
    test('can start and stop container', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
        } finally {
            await sim.close();
        }
    });

    test('get app version', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());
            const resp = await app.getVersion();

            console.log(resp);

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");
            expect(resp).toHaveProperty("testMode");
            expect(resp).toHaveProperty("major");
            expect(resp).toHaveProperty("minor");
            expect(resp).toHaveProperty("patch");
        } finally {
            await sim.close();
        }
    });

    test('get address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            const addr = await app.getAddressAndPubKey("m/44'/5757'/5'/0/0", true);
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_addr_raw = "0252dab95065cd31ae6f8ece65fffd2e904b203268a5923fa85e5db793698d753a";
            const expected_addr = "";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test('show address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/5757'/5'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expected_publicKey = "0327ae12779c24a1b242fe609d772f4c610a120d0b96a524022864e77a3b869d23";
            const expected_address = "";

            expect(response.publicKey.toString('hex')).toEqual(expected_publicKey);
            expect(response.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    // FIXME: Temporarily disabling until we connect the parser to the UI
    test('sign', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            // Do not await.. we need to click asynchronously
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", "1234");
            await Zemu.sleep(2000);

            await sim.clickBoth();

            let signature = await signatureRequest;
            console.log(signature)

            expect(signature.returnCode).toEqual(0x9000);

            // TODO: Verify signature
        } finally {
            await sim.close();
        }
    });

});
