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

import Zemu, {DEFAULT_START_OPTIONS, IDeviceModel} from '@zondax/zemu'
import StacksApp from "@zondax/ledger-stacks";

import {
  AddressVersion,
  createMessageSignature,
  createTransactionAuthField,
  sigHashPreSign,
  makeSTXTokenTransfer,
  makeUnsignedContractCall,
  makeUnsignedSTXTokenTransfer,
  PubKeyEncoding,
  privateKeyToPublic,
  standardPrincipalCV,
  TransactionSigner,
  uintCV,
} from "@stacks/transactions";
import {STACKS_TESTNET} from "@stacks/network";
import {ec as EC} from "elliptic";

const sha512_256 = require('js-sha512').sha512_256;

const Resolve = require("path").resolve;
const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')

const models: IDeviceModel[] = [
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
      const app = new StacksApp(sim.getTransport());

      const blob = Buffer.from("80800000000400d386442122c88878ae04c5726762477f4ef09ffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000000051a3b471808467d33eec688b7a7a75f06aad921ba6e000000000000007b74657374206d656d6f00000000000000000000000000000000000000000000000000", "hex");

      // Do not await.. we need to click asynchronously
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndApprove(".", "${m.prefix.toLowerCase()}-sign");

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
      const app = new StacksApp(sim.getTransport());

      const blob = Buffer.from("80800000000400d386442122c88878ae04c5726762477f4ef09ffe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030200000001000216bed38c2aadffa348931bcb542880ff79d607afec03000000000000303900051a3b471808467d33eec688b7a7a75f06aad921ba6e000000000000007b74657374206d656d6f00000000000000000000000000000000000000000000000000", "hex");
      // Do not await.. we need to click asynchronously
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndApprove(".", "sign_stx_token_transfer_with_postcondition");

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
      const app = new StacksApp(sim.getTransport());

      const blob = Buffer.from("80800000000400143e543243dfcd8c02a12ad7ea371bd07bc91df90000000000000000000000000000000000013a078ceb0c539e278bfa3ab99b0e5d99579ac9c79d0899d91b798390de32521414dded3560f11c212152fc3e2d66af111002139c1597458665264d98c0d3a804030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a2020202020202020202028626567696e20287661722d7365742062617220282f20782079292920286f6b20287661722d6765742062617229292929", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndApprove(".", "sign_standard_smart_contract_tx");

      const signature = await signatureRequest;
      console.log("Signature: ");
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
      const app = new StacksApp(sim.getTransport());

      const blob = Buffer.from("808000000004003b471808467d33eec688b7a7a75f06aad921ba6e000000000000000100000000000000000000134ab418c3422c600bfeffb1a322b78edab12961fdea48f34cbbb4eae42a4a53401bf2a0d680e819028276cfa13c672a8031ddd17b46fda70a037fefb20e9e9203020000000101021a3b471808467d33eec688b7a7a75f06aad921ba6e1a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73030000000000000064021a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c6414757365722d73656e642d737461636b61726f6f7300000001051a2d89de56fd4db19741957831926e9ba96cf04158", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndApprove(".", "sign_contract_call_with_postcondition_tx");

      const signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });
});
