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

import Zemu, {DEFAULT_START_OPTIONS, DeviceModel} from '@zondax/zemu'
import BlockstackApp from "@zondax/ledger-blockstack";

import {
  AddressVersion,
  createMessageSignature,
  createStacksPrivateKey,
  createTransactionAuthField,
  isCompressed,
  makeSigHashPreSign,
  makeSTXTokenTransfer,
  makeUnsignedContractCall,
  makeUnsignedSTXTokenTransfer,
  PubKeyEncoding,
  pubKeyfromPrivKey,
  publicKeyToString,
  standardPrincipalCV,
  TransactionSigner,
  uintCV,
} from "@stacks/transactions";
import {StacksTestnet} from "@stacks/network";
import {ec as EC} from "elliptic";
import {AnchorMode} from "@stacks/transactions/src/constants";
//import {recoverPublicKey} from "noble-secp256k1";

const BN = require("bn.js");
const sha512_256 = require('js-sha512').sha512_256;

const Resolve = require("path").resolve;
const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')

const models: DeviceModel[] = [
  {name: 'nanos', prefix: 'S', path: APP_PATH_S},
  {name: 'nanox', prefix: 'X', path: APP_PATH_X}
];

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young";
const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: true,
}

jest.setTimeout(60000);

beforeAll(async () => {
  await Zemu.checkAndPullImage()
})

describe.skip("Skipped", function () {
  test.each(models)("sign2", async function (m) {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start({...defaultOptions, model: m.name})
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000400d386442122c88878ae04c5726762477f4ef09ffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000000051a3b471808467d33eec688b7a7a75f06aad921ba6e000000000000007b74657374206d656d6f00000000000000000000000000000000000000000000000000", "hex");

      // Do not await.. we need to click asynchronously
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "${m.prefix.toLowerCase()}-sign", 9);

      const signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);

      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.each(models)("sign stx_token_transfer_with_postcondition", async function (m) {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start({...defaultOptions, model: m.name})
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000400d386442122c88878ae04c5726762477f4ef09ffe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030200000001000216bed38c2aadffa348931bcb542880ff79d607afec03000000000000303900051a3b471808467d33eec688b7a7a75f06aad921ba6e000000000000007b74657374206d656d6f00000000000000000000000000000000000000000000000000", "hex");
      // Do not await.. we need to click asynchronously
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign_stx_token_transfer_with_postcondition", 13);

      const signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);

      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.each(models)("sign sponsored_smart_contract_tx", async function (m) {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start({...defaultOptions, model: m.name})
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000500143e543243dfcd8c02a12ad7ea371bd07bc91df9000000000000000000000000000000000001da16615641474cb924c7c21ea64ba9398108ee4eeff379b24da7f93ad207a0693b53501ad3a83ee3878475afb86d1a4b532862372d068771a330c3a49489e40d003b471808467d33eec688b7a7a75f06aad921ba6e000000000000000000000000000000000000c386b06eda046b9b19e99506bd694af47286aef3fb358429309ffccea7052837261410014df4c29555e84240461c82b5a0c7dbf18d53551638790659a252efb8030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a202020200302202020202028626567696e20287661722d7365742062617220282f2078200115292920286f6b20287661722d6765742062617229292929", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign_sponsored_smart_contract_tx", 6);

      const signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.each(models)("sign standard_smart_contract_tx", async function (m) {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start({...defaultOptions, model: m.name})
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000400143e543243dfcd8c02a12ad7ea371bd07bc91df90000000000000000000000000000000000013a078ceb0c539e278bfa3ab99b0e5d99579ac9c79d0899d91b798390de32521414dded3560f11c212152fc3e2d66af111002139c1597458665264d98c0d3a804030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a2020202020202020202028626567696e20287661722d7365742062617220282f20782079292920286f6b20287661722d6765742062617229292929", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign_standard_smart_contract_tx", 6);

      const signature = await signatureRequest;
      console.log("Signature: ");
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });


  test.each(models)("sign sponsored_contract_call_tx", async function (m) {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start({...defaultOptions, model: m.name})
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("808000000005002d89de56fd4db19741957831926e9ba96cf04158000000000000000000000000000000000001c88dc2ad9b081db525b68a04a4e9a021f05d6c8500b43ff01360f255826f3676636bcd0494a55bfd529028fe8c1b1e93ad23b75c31b29cee369d8bf5f643d478003b471808467d33eec688b7a7a75f06aad921ba6e0000000000000000000000000000000000001fc1ecc42a7b62598a6969cc0af77d81992839e203946867e603d4d8d2a3653a7efc00d16423b035f82d5550f26d3d59205b0cf578a93618c3eb7f50dc12f73c030200000000021a143e543243dfcd8c02a12ad7ea371bd07bc91df90b68656c6c6f2d776f726c64077365742d6261720000000200000000000000000000000000000000060000000000000000000000000000000002", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", "sign_sponsored_contract_call_tx", 9);

      const signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.each(models)("sign contract_call_with_postcondition_tx", async function (m) {
    jest.setTimeout(30000);
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start({...defaultOptions, model: m.name})
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("808000000004003b471808467d33eec688b7a7a75f06aad921ba6e000000000000000100000000000000000000134ab418c3422c600bfeffb1a322b78edab12961fdea48f34cbbb4eae42a4a53401bf2a0d680e819028276cfa13c672a8031ddd17b46fda70a037fefb20e9e9203020000000101021a3b471808467d33eec688b7a7a75f06aad921ba6e1a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73030000000000000064021a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c6414757365722d73656e642d737461636b61726f6f7300000001051a2d89de56fd4db19741957831926e9ba96cf04158", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", "sign_contract_call_with_postcondition_tx", 14);

      const signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.each(models)("sign sponsored_contract_call_tx_with_7_postconditions", async function (m) {
    // Update the timeout limit because this transaction is huge
    // so It does take time showing all the items them signing it
    jest.setTimeout(40000);
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start({...defaultOptions, model: m.name})
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("808000000004002d89de56fd4db19741957831926e9ba96cf04158000000000000000300000000000000000001b019126ffa434bd7c816b3e1daa3163e322aae6cde06585d22d46286570e4a491eecc2dcd214a42eae62584ddbe8a96382ff1f34edb4ecedeab0a6b6b1e07d2003020000000701031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73010000000000000064000103000000000000007c01031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f7303000000000000006400010300000000000000f701031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73050000000000000064000103000000000000017202031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c64056e616d657302000000040000006410021a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640f73656e642d737461636b61726f6f7300000001051a3b471808467d33eec688b7a7a75f06aad921ba6e", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", "sign_sponsored_contract_call_tx_with_7_postconditions", 37);

      const signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });
});
