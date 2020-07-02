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
    it('can start and stop container', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
        } finally {
            await sim.close();
        }
    });

    it('app version', async function () {
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

    it('get address', async function () {
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
        const snapshotPrefixGolden = "snapshots/show-address/";
        const snapshotPrefixTmp = "snapshots-tmp/show-address/";
        let snapshotCount = 0;

        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            // Derivation path. First 3 items are automatically hardened!
            const path = "m/44'/5757'/5'/0/3";
            const respRequest = app.showAddressAndPubKey(path);

            // We need to wait until the app responds to the APDU
            await Zemu.sleep(2000);

            // Now navigate the address / path
            await sim.snapshot(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickRight(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickRight(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickRight(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickRight(`${snapshotPrefixTmp}${snapshotCount++}.png`);
            await sim.clickBoth(`${snapshotPrefixTmp}${snapshotCount++}.png`);

            const resp = await respRequest;
            console.log(resp);

            compareSnapshots(snapshotPrefixTmp, snapshotPrefixGolden, snapshotCount);

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");

            const expected_address_string = "STGZNGF9PTR3ZPJN9J67WRYV5PSV783JY9ZMT3Y6";
            const expected_publicKey = "02beafa347af54948b214106b9972cc4a05a771a2573f32905c48e4dc697171e60";

            expect(resp.address).toEqual(expected_address_string);
            expect(resp.publicKey.toString('hex')).toEqual(expected_publicKey);
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
            const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
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

    test('sign sponsored_smart_contract_transaction', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

	        const blob = Buffer.from("80800000000400149be4d6c4667e4fb6d461e7c8378fa5a5e10c9f000000000000000000000000000000c800018911d4ae201d2139a69d73c725b955314c65b3de834232e9dc194cfd723b3d4c381d13280b1621fc01061dd31fd88c4bf94632649504ff7b2106742ed4e15fd0030200000000010b6d795f636f6e74726163740000075228646566696e652d636f6e7374616e74206275726e2d6164647265737320275350303030303030303030303030303030303030303032513656463738290a28646566696e652d70726976617465202870726963652d66756e6374696f6e20286e616d652075696e7429290a202028696620283c206e616d65207531303030303029207531303030207531303029290a2020202020202020200a28646566696e652d6d6170206e616d652d6d6170200a202028286e616d652075696e7429292028286f776e6572207072696e636970616c2929290a28646566696e652d6d6170207072656f726465722d6d61700a202028286e616d652d686173682028627566662032302929290a202028286275796572207072696e636970616c292028706169642075696e742929290a2020202020202020200a28646566696e652d7075626c696320287072656f72646572200a20202020202020202020202020202020286e616d652d6861736820286275666620323029290a20202020202020202020202020202020286e616d652d70726963652075696e7429290a2020286966202869732d6f6b2028636f6e74726163742d63616c6c3f202e746f6b656e7320746f6b656e2d7472616e736665720a202020202020202020202020202020206275726e2d61646472657373206e616d652d707269636529290a20202020202028626567696e20286d61702d696e73657274207072656f726465722d6d61700a202020202020202020202020202020202020202020287475706c6520286e616d652d68617368206e616d652d6861736829290a202020202020202020202020202020202020202020287475706c65202870616964206e616d652d7072696365290a202020202020202020202020202020202020202020202020202020202862757965722074782d73656e6465722929290a20202020202020202020202020286f6b20753029290a202020202020286572722022746f6b656e207061796d656e74206661696c65642e222929290a0a28646566696e652d7075626c696320287265676973746572200a2020202020202020202020202020202028726563697069656e742d7072696e636970616c207072696e636970616c290a20202020202020202020202020202020286e616d652075696e74290a202020202020202020202020202020202873616c742075696e7429290a2020286c65742028287072656f726465722d656e7472790a20202020202020202028756e7772617021203b3b206e616d65205f6d7573745f2068617665206265656e207072656f7264657265642e0a2020202020202020202020286d61702d6765743f207072656f726465722d6d61700a20202020202020202020202020287475706c6520286e616d652d686173682028686173683136302028786f72206e616d652073616c7429292929290a20202020202020202020202865727220226e6f207072656f7264657220666f756e64222929290a2020202020202020286e616d652d656e747279200a202020202020202020286d61702d6765743f206e616d652d6d617020287475706c6520286e616d65206e616d6529292929290a202020202869662028616e640a2020202020202020203b3b206e616d652073686f756c646e2774202a616c72656164792a2065786973740a2020202020202020202869732d6e6f6e65206e616d652d656e747279290a2020202020202020203b3b207072656f72646572206d7573742068617665207061696420656e6f7567680a202020202020202020283c3d202870726963652d66756e6374696f6e206e616d6529200a20202020202020202020202020286765742070616964207072656f726465722d656e74727929290a2020202020202020203b3b207072656f72646572206d7573742068617665206265656e207468652063757272656e74207072696e636970616c0a2020202020202020202869732d65712074782d73656e6465720a202020202020202020202020202028676574206275796572207072656f726465722d656e7472792929290a20202020202020202869662028616e640a2020202020202020202020202020286d61702d696e73657274206e616d652d6d61700a202020202020202020202020202020202020202020202020287475706c6520286e616d65206e616d6529290a202020202020202020202020202020202020202020202020287475706c6520286f776e657220726563697069656e742d7072696e636970616c2929290a2020202020202020202020202020286d61702d64656c657465207072656f726465722d6d61700a202020202020202020202020202020202020202020202020287475706c6520286e616d652d686173682028686173683136302028786f72206e616d652073616c742929292929290a202020202020202020202020286f6b207530290a2020202020202020202020202865727220226661696c656420746f20696e73657274206e6577206e616d6520656e7472792229290a2020202020202020286572722022696e76616c6964206e616d6520726567697374657222292929290a", "hex");
            const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
            //await sim.clickRight();
            //await sim.clickRight();
            // await sim.clickBoth();


             let signature = await signatureRequest;
             console.log("SIGNATUREEEEE")
             console.log(signature)

             expect(signature.returnCode).toEqual(0x9000);

             // TODO: Verify signature
         } finally {
             await sim.close();
         }
     });

});
