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

            const response = await app.getAddressAndPubKey("m/44'/5757'/5'/0/0", true);
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expectedPublicKey = "0252dab95065cd31ae6f8ece65fffd2e904b203268a5923fa85e5db793698d753a";
            const expectedAddr = "ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5";

            expect(response.publicKey.toString('hex')).toEqual(expectedPublicKey);
            expect(response.address).toEqual(expectedAddr);
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
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const response = await addrRequest;
            console.log(response)
            expect(response.returnCode).toEqual(0x9000);

            const expectedPublicKey = "0327ae12779c24a1b242fe609d772f4c610a120d0b96a524022864e77a3b869d23";
            const expectedAddr = "STC47MG6DWWH30RJK8V10AWE7PP63DADXHV76MAQ";

            expect(response.publicKey.toString('hex')).toEqual(expectedPublicKey);
            expect(response.address).toEqual(expectedAddr);
        } finally {
            await sim.close();
        }
    });

    test('sign', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

	    const blob = Buffer.from("00000000010400149be4d6c4667e4fb6d461e7c8378fa5a5e10c9f000000000000000a00000000000004e200010e997280fe04c9976e70d90a93b9f86507247f5e9fa78ec95cd4eebb27b23f3338a13f549bee779b646bffff41611c9eae53b65e6b7a911b00c906a36ad5920a0302000000000005169eb0a31b22af43679e4f58ce400ed641c28113a6000000000000138800000000000000000000000000000000000000000000000000000000000000000000","hex");
            // Do not await.. we need to click asynchronously
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);
            await Zemu.sleep(2000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();

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
