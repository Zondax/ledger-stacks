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

import jest, { expect } from "jest";
import Zemu from "@zondax/zemu";
import NetworkVersion from "@zondax/ledger-blockstack";
import BlockstackApp from "@zondax/ledger-blockstack";
import {
  broadcastTransaction,
  createMessageSignature,
  makeSigHashPreSign,
  makeSTXTokenTransfer,
  makeUnsignedSTXTokenTransfer,
  pubKeyfromPrivKey,
  AddressVersion,
  standardPrincipalCV,
  publicKeyToString,
  TransactionSigner,
  createStacksPrivateKey,
  isCompressed,
  PubKeyEncoding,
  SpendingCondition,
  createTransactionAuthField,
  UnsignedMultiSigTokenTransferOptions
} from "@stacks/transactions";
import { StacksTestnet } from "@stacks/network";
import { ec as EC } from "elliptic";
import {recoverPublicKey} from "noble-secp256k1";

const BN = require("bn.js");

const Resolve = require("path").resolve;
const APP_PATH_S = Resolve("../app/bin/app_s.elf");
const APP_PATH_X = Resolve("../app/bin/app_x.elf");

const models = [
  { model:'nanos', prefix: 'S', path: APP_PATH_S},
  { model: 'nanox', prefix: 'X', path: APP_PATH_X}
];

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young";
const simOptions = {
  logging: true,
  start_delay: 3000,
  custom: `-s "${APP_SEED}"`
  , X11: true
};

jest.setTimeout(20000);

describe("Basic checks", function() {

  for (let nanoModel of models) {
    it(`${nanoModel.prefix} - can start and stop container`, async function() {
      const sim = new Zemu(nanoModel.path);
      try {
        await sim.start({ model: nanoModel.model, ...simOptions});
      } finally {
        await sim.close();
      }
    });

    it(`${nanoModel.prefix} - app version`, async function() {
      const sim = new Zemu(nanoModel.path);
      try {
        await sim.start({ model: nanoModel.model, ...simOptions});
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

    it(`${nanoModel.prefix} - get address`, async function() {
      const sim = new Zemu(nanoModel.path);
      try {
        await sim.start({ model: nanoModel.model, ...simOptions});
        const app = new BlockstackApp(sim.getTransport());

        const response = await app.getAddressAndPubKey("m/44'/5757'/5'/0/0", AddressVersion.MainnetSingleSig, true);
        console.log(response);
        expect(response.returnCode).toEqual(0x9000);

        const expectedPublicKey = "0252dab95065cd31ae6f8ece65fffd2e904b203268a5923fa85e5db793698d753a";
        const expectedAddr = "SP39RCH114B48GY5E0K2Q4SV28XZMXW4ZZRQXY3V7";

        expect(response.publicKey.toString("hex")).toEqual(expectedPublicKey);
        expect(response.address).toEqual(expectedAddr);
      } finally {
        await sim.close();
      }
    });

    test(`${nanoModel.prefix} - show address`, async function() {
      const sim = new Zemu(nanoModel.path);
      try {
        await sim.start({ model: nanoModel.model, ...simOptions});
        const app = new BlockstackApp(sim.getTransport());

        // Derivation path. First 3 items are automatically hardened!
        const path = "m/44'/5757'/5'/0/3";

        const respRequest = app.showAddressAndPubKey(path, AddressVersion.MainnetSingleSig);
        // Wait until we are not in the main menu
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

        await sim.compareSnapshotsAndAccept(".", `${nanoModel.prefix.toLowerCase()}-show-address`, nanoModel.model === 'nanos' ? 2 : 2);

        const resp = await respRequest;
        console.log(resp);

        expect(resp.returnCode).toEqual(0x9000);
        expect(resp.errorMessage).toEqual("No errors");

        const expected_address_string = "SPGZNGF9PTR3ZPJN9J67WRYV5PSV783JY9FDC6ZR";
        const expected_publicKey = "02beafa347af54948b214106b9972cc4a05a771a2573f32905c48e4dc697171e60";

        expect(resp.address).toEqual(expected_address_string);
        console.log("Response address ", resp.address)
        expect(resp.publicKey.toString("hex")).toEqual(expected_publicKey);


        const response_t = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig);
        const expected_testnet_address_string = "STGZNGF9PTR3ZPJN9J67WRYV5PSV783JY9ZMT3Y6";
        expect(response_t.address).toEqual(expected_testnet_address_string);
      } finally {
        await sim.close();
      }
    });

    test(`${nanoModel.prefix} - test signature`, async function() {
      const sim = new Zemu(nanoModel.path);
      const network = new StacksTestnet();
      const senderKey = "2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216";
      const path = "m/44'/5757'/0'/0/0";

      try {
        await sim.start({ model: nanoModel.model, ...simOptions});
        const app = new BlockstackApp(sim.getTransport());

        // Get pubkey and check
        const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig);
        console.log(pkResponse);
        expect(pkResponse.returnCode).toEqual(0x9000);
        expect(pkResponse.errorMessage).toEqual("No errors");
        const testPublicKey = pkResponse.publicKey.toString("hex");
        console.log("publicKey ", testPublicKey);

        // uses the provided privKey to derive a pubKey using stacks API
        // we expect the derived publicKey to be same as the ledger-app
        const expectedPublicKey = publicKeyToString(pubKeyfromPrivKey(senderKey));

        expect(testPublicKey).toEqual("02" + expectedPublicKey.slice(2, 2 + 32 * 2));

        const signedTx = await makeSTXTokenTransfer({
          senderKey,
          recipient: "ST12KRFTX4APEB6201HY21JMSTPSSJ2QR28MSPPWK",
          network,
          nonce: new BN(0),
          fee: new BN(180),
          amount: new BN(1)
        });

        const unsignedTx = await makeUnsignedSTXTokenTransfer({
          recipient: "ST12KRFTX4APEB6201HY21JMSTPSSJ2QR28MSPPWK",
          network,
          nonce: new BN(0),
          fee: new BN(180),
          amount: new BN(1),
          publicKey: testPublicKey
        });

        // tx_hash:  bdb9f5112cf2333e6b8e6fca88764083332a41923dadab84cd5065a7a483a3f6
        // digest:   dd46e325d5a631c99e84f3018a839c229453ab7fd8d16a6dadd7f7cf51e604c3

        console.log("tx_hash: ", unsignedTx.signBegin());

        const sigHashPreSign = makeSigHashPreSign(
          unsignedTx.signBegin(),
          unsignedTx.auth.authType,
          unsignedTx.auth.spendingCondition?.fee,
          unsignedTx.auth.spendingCondition?.nonce);

        console.log("sigHashPreSign: ", sigHashPreSign);

        const blob = Buffer.from(unsignedTx.serialize());

        // Check the signature
        const signatureRequest = app.sign(path, blob);

        // Wait until we are not in the main men
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

        await sim.compareSnapshotsAndAccept(".", `${nanoModel.prefix.toLowerCase()}-signatureTest`, nanoModel.model === 'nanos' ? 8 : 7);

        let signature = await signatureRequest;
        console.log(signature);

        let js_signature = signedTx.auth.spendingCondition?.signature.signature;
        console.log("js_signature ", js_signature);
        console.log("ledger-postSignHash: ", signature.postSignHash.toString("hex"));
        console.log("ledger-compact: ", signature.signatureCompact.toString("hex"));
        console.log("ledger-vrs", signature.signatureVRS.toString("hex"));
        console.log("ledger-DER: ", signature.signatureDER.toString("hex"));

        unsignedTx.auth.spendingCondition.signature = createMessageSignature(signature.signatureVRS.toString("hex"));
        //unsignedTx.auth.spendingCondition.signature.signature = signature.signatureVRS.toString('hex');

        console.log("unsignedTx serialized ", unsignedTx.serialize().toString("hex"));
        //
        // const broadcast = await broadcastTransaction(unsignedTx, network);
        // console.log(broadcast);
        //
        // expect(broadcast.reason).not.toBe("SignatureValidation");
        //
        // expect(signature.returnCode).toEqual(0x9000);
        //
        // const ec = new EC("secp256k1");
        // const sig = signature.signatureDER.toString("hex");
        // const pk = pkResponse.publicKey.toString("hex");
        // console.log(sigHashPreSign);
        // console.log(sig);
        // console.log(pk);
        // const signatureOk = ec.verify(sigHashPreSign, sig, pk, "hex");
        // expect(signatureOk).toEqual(true);

      } finally {
        await sim.close();
      }
    });

    test(`${nanoModel.prefix} - multisig`, async function() {

        const sim = new Zemu(nanoModel.path);
        const network = new StacksTestnet();
        const senderKey = "2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216";
        const path = "m/44'/5757'/0'/0/0";

        try {
            await sim.start({ model: nanoModel.model, ...simOptions});
            const app = new BlockstackApp(sim.getTransport());

            // Get pubkey and check
            const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig);
            console.log(pkResponse);
            expect(pkResponse.returnCode).toEqual(0x9000);
            expect(pkResponse.errorMessage).toEqual("No errors");
            const devicePublicKey = pkResponse.publicKey.toString("hex");

            const recipient = standardPrincipalCV('ST2XADQKC3EPZ62QTG5Q2RSPV64JG6KXCND0PHT7F');
            const amount = new BN(2500000);
            const fee = new BN(0);
            const nonce = new BN(0);
            const memo = 'multisig tx';

            const priv_key_signer0 = createStacksPrivateKey('219af15a772e3478a26bbe669b524e9e86c1aaa4c2ae640cd432a29431a4cb0101');
            const pub_key_signer0 = '03c00170321c5ce931d3201927ff6b1993c350f72af5483b9d75e8505ef10aed8c';
            const pubKeyStrings = [pub_key_signer0, devicePublicKey];

            const unsignedTx = await makeUnsignedSTXTokenTransfer({
                recipient: recipient,
                network,
                nonce: nonce,
                fee: fee,
                amount: amount,
                memo: memo,
                numSignatures: 2,
                publicKeys: pubKeyStrings,
            });
            const sigHashPreSign = makeSigHashPreSign(
                unsignedTx.signBegin(),
                unsignedTx.auth.authType,
                unsignedTx.auth.spendingCondition?.fee,
                unsignedTx.auth.spendingCondition?.nonce).toString('hex');

            // Signer0 sign the transaction and append its post_sig_hash to the transaction buffer
            const signer0 = new TransactionSigner(unsignedTx);

            signer0.signOrigin(priv_key_signer0);

            // get signer0 post_sig_hash
            const postsig_hash_blob = Buffer.from(signer0.sigHash, 'hex');

            const serializeTx = unsignedTx.serialize().toString('hex');
            const publicKey = pubKeyfromPrivKey('219af15a772e3478a26bbe669b524e9e86c1aaa4c2ae640cd432a29431a4cb0101');
            var key_type;
            if (isCompressed(publicKey)) {
                key_type =  PubKeyEncoding.Compressed;

            } else {
                key_type =  PubKeyEncoding.Uncompressed;
            }
            const blob3 = Buffer.alloc(1, key_type);
            const signature_signer0_hex = signer0.transaction.auth.spendingCondition.fields[0].contents.data;
            const signer0_signature = Buffer.from(signature_signer0_hex, 'hex');

            var blob1 = Buffer.from(serializeTx, 'hex');
            // Pass a full transaction buffer, and the previous signer postsig_hash,  pubkey type
            // and vrs signature
            var arr = [blob1, postsig_hash_blob, blob3, signer0_signature];
            const blob = Buffer.concat(arr);

            // Signs the transaction that includes the previous signer post_sig_hash
            const signatureRequest = app.sign(path, blob);

            // Wait until we are not in the main men
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${nanoModel.prefix.toLowerCase()}-multisigTest`, nanoModel.model === 'nanos' ? 8 : 7);

            let signature = await signatureRequest;
            console.log(signature);

            //let js_signature = signedTx.auth.spendingCondition?.signature.signature;
            //console.log("js_signature ", js_signature);
            console.log("ledger-postSignHash: ", signature.postSignHash.toString("hex"));
            console.log("ledger-compact: ", signature.signatureCompact.toString("hex"));
            console.log("ledger-vrs", signature.signatureVRS.toString("hex"));
            console.log("ledger-DER: ", signature.signatureDER.toString("hex"));

            var signedTx = signer0.transaction;
            signedTx.auth.spendingCondition.fields.push(createTransactionAuthField(signature.signatureVRS.toString('hex')));

            // Verifies the first signer signature using the preSigHash and signer0 data
            const ec = new EC("secp256k1");
            const signer0_signature_obj = {r: signature_signer0_hex.substr(2, 64), s: signature_signer0_hex.substr(66, 64) };
            const signatureOk = ec.verify(sigHashPreSign, signer0_signature_obj, pub_key_signer0, "hex");
            expect(signatureOk).toEqual(true);

            // Verifies that the second signer's signature is ok
            const signature1 = signature.signatureVRS.toString("hex");
            const signature1_obj = {r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
            const signature1Ok = ec.verify(signer0.sigHash, signature1_obj, devicePublicKey, "hex");
            expect(signature1Ok).toEqual(true);

        } finally {
            await sim.close();
        }
      });

  }

  test.skip("sign", async function() {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000400d386442122c88878ae04c5726762477f4ef09ffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000000051a3b471808467d33eec688b7a7a75f06aad921ba6e000000000000007b74657374206d656d6f00000000000000000000000000000000000000000000000000", "hex");

      // Do not await.. we need to click asynchronously
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign", 9);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);

      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("multisig sign", async function() {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000400d386442122c88878ae04c5726762477f4ef09ffe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000000051a3b471808467d33eec688b7a7a75f06aad921ba6e000000000000007b74657374206d656d6f00000000000000000000000000000000000000000000000000", "hex");

      // Do not await.. we need to click asynchronously
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign", 9);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);

      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("sign stx_token_transfer_with_postcondition", async function() {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000400d386442122c88878ae04c5726762477f4ef09ffe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030200000001000216bed38c2aadffa348931bcb542880ff79d607afec03000000000000303900051a3b471808467d33eec688b7a7a75f06aad921ba6e000000000000007b74657374206d656d6f00000000000000000000000000000000000000000000000000", "hex");
      // Do not await.. we need to click asynchronously
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign_stx_token_transfer_with_postcondition", 13);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);

      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("sign sponsored_smart_contract_tx", async function() {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000500143e543243dfcd8c02a12ad7ea371bd07bc91df9000000000000000000000000000000000001da16615641474cb924c7c21ea64ba9398108ee4eeff379b24da7f93ad207a0693b53501ad3a83ee3878475afb86d1a4b532862372d068771a330c3a49489e40d003b471808467d33eec688b7a7a75f06aad921ba6e000000000000000000000000000000000000c386b06eda046b9b19e99506bd694af47286aef3fb358429309ffccea7052837261410014df4c29555e84240461c82b5a0c7dbf18d53551638790659a252efb8030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a202020200302202020202028626567696e20287661722d7365742062617220282f2078200115292920286f6b20287661722d6765742062617229292929", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign_sponsored_smart_contract_tx", 6);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("sign standard_smart_contract_tx", async function() {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("80800000000400143e543243dfcd8c02a12ad7ea371bd07bc91df90000000000000000000000000000000000013a078ceb0c539e278bfa3ab99b0e5d99579ac9c79d0899d91b798390de32521414dded3560f11c212152fc3e2d66af111002139c1597458665264d98c0d3a804030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a2020202020202020202028626567696e20287661722d7365742062617220282f20782079292920286f6b20287661722d6765742062617229292929", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign_standard_smart_contract_tx", 6);

      let signature = await signatureRequest;
      console.log("Signature: ");
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("sign standard_contract_call_tx", async function() {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("808000000004003a8dda5c8785cbba6daec2013bdac06b98202bc30000000000000000000000000000000000004c4c6b830501e8853f4c5b94fa699a6a14b2c07fa1d2b969fe61bcc830aefe3b44cb3a294f33fd615661b6a6b593108c588d92b930ef68225d1bb4417c023ed9030200000000021a143e543243dfcd8c02a12ad7ea371bd07bc91df90b68656c6c6f2d776f726c64077365742d6261720000000200000000000000000000000000000000060000000000000000000000000000000002", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

      await sim.compareSnapshotsAndAccept(".", "sign_standard_contract_call_tx", 9);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("sign sponsored_contract_call_tx", async function() {
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("808000000005002d89de56fd4db19741957831926e9ba96cf04158000000000000000000000000000000000001c88dc2ad9b081db525b68a04a4e9a021f05d6c8500b43ff01360f255826f3676636bcd0494a55bfd529028fe8c1b1e93ad23b75c31b29cee369d8bf5f643d478003b471808467d33eec688b7a7a75f06aad921ba6e0000000000000000000000000000000000001fc1ecc42a7b62598a6969cc0af77d81992839e203946867e603d4d8d2a3653a7efc00d16423b035f82d5550f26d3d59205b0cf578a93618c3eb7f50dc12f73c030200000000021a143e543243dfcd8c02a12ad7ea371bd07bc91df90b68656c6c6f2d776f726c64077365742d6261720000000200000000000000000000000000000000060000000000000000000000000000000002", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", "sign_sponsored_contract_call_tx", 9);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("sign contract_call_with_postcondition_tx", async function() {
    jest.setTimeout(30000);
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("808000000004003b471808467d33eec688b7a7a75f06aad921ba6e000000000000000100000000000000000000134ab418c3422c600bfeffb1a322b78edab12961fdea48f34cbbb4eae42a4a53401bf2a0d680e819028276cfa13c672a8031ddd17b46fda70a037fefb20e9e9203020000000101021a3b471808467d33eec688b7a7a75f06aad921ba6e1a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73030000000000000064021a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c6414757365722d73656e642d737461636b61726f6f7300000001051a2d89de56fd4db19741957831926e9ba96cf04158", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", "sign_contract_call_with_postcondition_tx", 14);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });

  test.skip("sign sponsored_contract_call_tx_with_7_postconditions", async function() {
    // Update the timeout limit because this transaction is huge
    // so It does take time showing all the items them signing it
    jest.setTimeout(40000);
    const sim = new Zemu(APP_PATH_S);
    try {
      await sim.start(simOptions);
      const app = new BlockstackApp(sim.getTransport());

      const blob = Buffer.from("808000000004002d89de56fd4db19741957831926e9ba96cf04158000000000000000300000000000000000001b019126ffa434bd7c816b3e1daa3163e322aae6cde06585d22d46286570e4a491eecc2dcd214a42eae62584ddbe8a96382ff1f34edb4ecedeab0a6b6b1e07d2003020000000701031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73010000000000000064000103000000000000007c01031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f7303000000000000006400010300000000000000f701031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73050000000000000064000103000000000000017202031a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c641a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c64056e616d657302000000040000006410021a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640f73656e642d737461636b61726f6f7300000001051a3b471808467d33eec688b7a7a75f06aad921ba6e", "hex");
      const signatureRequest = app.sign("m/44'/5757'/5'/0/0", blob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000);

      await sim.compareSnapshotsAndAccept(".", "sign_sponsored_contract_call_tx_with_7_postconditions", 37);

      let signature = await signatureRequest;
      console.log(signature);

      expect(signature.returnCode).toEqual(0x9000);
      // TODO: Verify signature
    } finally {
      await sim.close();
    }
  });
});
