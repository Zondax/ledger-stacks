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
	        console.log("stx_token_transfer SIZE: " + blob.length)
            // Do not await.. we need to click asynchronously
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);
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

    test('sign sponsored_smart_contract_tx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            const blob = Buffer.from("80800000000500143e543243dfcd8c02a12ad7ea371bd07bc91df9000000000000000000000000000000000001da16615641474cb924c7c21ea64ba9398108ee4eeff379b24da7f93ad207a0693b53501ad3a83ee3878475afb86d1a4b532862372d068771a330c3a49489e40d003b471808467d33eec688b7a7a75f06aad921ba6e000000000000000000000000000000000000c386b06eda046b9b19e99506bd694af47286aef3fb358429309ffccea7052837261410014df4c29555e84240461c82b5a0c7dbf18d53551638790659a252efb8030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a202020200302202020202028626567696e20287661722d7365742062617220282f2078200115292920286f6b20287661722d6765742062617229292929", "hex");
	    console.log("sponsored smart_contract_tx SIZE: " + blob.length)
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);
            await sim.clickRight();


             let signature = await signatureRequest;
             console.log("SIGNATUREEEEE")
             console.log(signature)

             expect(signature.returnCode).toEqual(0x9000);
             // TODO: Verify signature
         } finally {
             await sim.close();
         }
     });

    test('sign standard_smart_contract_tx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            const blob = Buffer.from("80800000000400143e543243dfcd8c02a12ad7ea371bd07bc91df90000000000000000000000000000000000013a078ceb0c539e278bfa3ab99b0e5d99579ac9c79d0899d91b798390de32521414dded3560f11c212152fc3e2d66af111002139c1597458665264d98c0d3a804030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a2020202020202020202028626567696e20287661722d7365742062617220282f20782079292920286f6b20287661722d6765742062617229292929", "hex");
	    console.log("standard_smart_contract_tx SIZE: " + blob.length)
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);
            await Zemu.sleep(1000);
            await sim.clickRight();
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
             console.log("SIGNATUREEEEE")
             console.log(signature)

             expect(signature.returnCode).toEqual(0x9000);
             // TODO: Verify signature
         } finally {
             await sim.close();
         }
     });

    test('sign standard_contract_call_tx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            const blob = Buffer.from("808000000004003a8dda5c8785cbba6daec2013bdac06b98202bc30000000000000000000000000000000000004c4c6b830501e8853f4c5b94fa699a6a14b2c07fa1d2b969fe61bcc830aefe3b44cb3a294f33fd615661b6a6b593108c588d92b930ef68225d1bb4417c023ed9030200000000021a143e543243dfcd8c02a12ad7ea371bd07bc91df90b68656c6c6f2d776f726c64077365742d6261720000000200000000000000000000000000000000060000000000000000000000000000000002", "hex");
	    console.log("standard_contract_call SIZE: " + blob.length)
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);
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
             console.log("SIGNATUREEEEE")
             console.log(signature)

             expect(signature.returnCode).toEqual(0x9000);
             // TODO: Verify signature
         } finally {
             await sim.close();
         }
     });

    test('sign sponsored_contract_call_tx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(simOptions);
            const app = new BlockstackApp(sim.getTransport());

            const blob = Buffer.from("808000000005002d89de56fd4db19741957831926e9ba96cf04158000000000000000000000000000000000001c88dc2ad9b081db525b68a04a4e9a021f05d6c8500b43ff01360f255826f3676636bcd0494a55bfd529028fe8c1b1e93ad23b75c31b29cee369d8bf5f643d478003b471808467d33eec688b7a7a75f06aad921ba6e0000000000000000000000000000000000001fc1ecc42a7b62598a6969cc0af77d81992839e203946867e603d4d8d2a3653a7efc00d16423b035f82d5550f26d3d59205b0cf578a93618c3eb7f50dc12f73c030200000000021a143e543243dfcd8c02a12ad7ea371bd07bc91df90b68656c6c6f2d776f726c64077365742d6261720000000200000000000000000000000000000000060000000000000000000000000000000002", "hex");
	    console.log("sponsored_contract_call SIZE: " + blob.length)
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);
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
             console.log("SIGNATUREEEEE")
             console.log(signature)

             expect(signature.returnCode).toEqual(0x9000);
             // TODO: Verify signature
         } finally {
             await sim.close();
         }
     });


});
