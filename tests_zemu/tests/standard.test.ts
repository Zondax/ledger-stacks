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

import Zemu, { DEFAULT_START_OPTIONS, DeviceModel } from '@zondax/zemu'
import BlockstackApp from '@zondax/ledger-blockstack'

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
  stringAsciiCV,
  stringUtf8CV,
  cvToHex
} from '@stacks/transactions'
import { StacksTestnet } from '@stacks/network'
import { ec as EC } from 'elliptic'
import { AnchorMode } from '@stacks/transactions/src/constants'
//import {recoverPublicKey} from "noble-secp256k1";

const sha512_256 = require('js-sha512').sha512_256
const BN = require('bn.js')

const Resolve = require('path').resolve
const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')

const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(60000)

const models: DeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
]

beforeAll(async () => {
  await Zemu.checkAndPullImage()
})

describe('Standard', function () {
  test.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      //await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, [1, 0, 0, 5, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, [1, 0, 0, 4, -5])
    } finally {
      await sim.close()
    }
  })

  test.each(models)(`get app version`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('testMode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })

  test.each(models)(`get address`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())

      const response = await app.getAddressAndPubKey("m/44'/5757'/5'/0/0", AddressVersion.MainnetSingleSig)
      console.log(response)
      expect(response.returnCode).toEqual(0x9000)

      const expectedPublicKey = '0252dab95065cd31ae6f8ece65fffd2e904b203268a5923fa85e5db793698d753a'
      const expectedAddr = 'SP39RCH114B48GY5E0K2Q4SV28XZMXW4ZZRQXY3V7'

      expect(response.publicKey.toString('hex')).toEqual(expectedPublicKey)
      expect(response.address).toEqual(expectedAddr)
    } finally {
      await sim.close()
    }
  })

  test.each(models)(`show address`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = "m/44'/5757'/5'/0/3"

      const respRequest = app.showAddressAndPubKey(path, AddressVersion.MainnetSingleSig)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      const expected_address_string = 'SPGZNGF9PTR3ZPJN9J67WRYV5PSV783JY9FDC6ZR'
      const expected_publicKey = '02beafa347af54948b214106b9972cc4a05a771a2573f32905c48e4dc697171e60'

      expect(resp.address).toEqual(expected_address_string)
      console.log('Response address ', resp.address)
      expect(resp.publicKey.toString('hex')).toEqual(expected_publicKey)

      const response_t = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      const expected_testnet_address_string = 'STGZNGF9PTR3ZPJN9J67WRYV5PSV783JY9ZMT3Y6'
      expect(response_t.address).toEqual(expected_testnet_address_string)
    } finally {
      await sim.close()
    }
  })

  test.each(models)(`sign`, async function (m) {
    const sim = new Zemu(m.path)
    const network = new StacksTestnet()
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())

      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const testPublicKey = pkResponse.publicKey.toString('hex')
      console.log('publicKey ', testPublicKey)

      // uses the provided privKey to derive a pubKey using stacks API
      // we expect the derived publicKey to be same as the ledger-app
      const expectedPublicKey = publicKeyToString(pubKeyfromPrivKey(senderKey))

      expect(testPublicKey).toEqual('02' + expectedPublicKey.slice(2, 2 + 32 * 2))

      const signedTx = await makeSTXTokenTransfer({
        anchorMode: AnchorMode.Any,
        senderKey,
        recipient: 'ST12KRFTX4APEB6201HY21JMSTPSSJ2QR28MSPPWK',
        network,
        nonce: new BN(0),
        fee: new BN(180),
        amount: new BN(1),
      })

      const unsignedTx = await makeUnsignedSTXTokenTransfer({
        anchorMode: AnchorMode.Any,
        recipient: 'ST12KRFTX4APEB6201HY21JMSTPSSJ2QR28MSPPWK',
        network,
        nonce: new BN(0),
        fee: new BN(180),
        amount: new BN(1),
        publicKey: testPublicKey,
      })

      // tx_hash:  bdb9f5112cf2333e6b8e6fca88764083332a41923dadab84cd5065a7a483a3f6
      // digest:   dd46e325d5a631c99e84f3018a839c229453ab7fd8d16a6dadd7f7cf51e604c3

      console.log('tx_hash: ', unsignedTx.signBegin())

      const sigHashPreSign = makeSigHashPreSign(
        unsignedTx.signBegin(),
        // @ts-ignore
        unsignedTx.auth.authType,
        unsignedTx.auth.spendingCondition?.fee,
        unsignedTx.auth.spendingCondition?.nonce,
      )

      console.log('sigHashPreSign: ', sigHashPreSign)

      const blob = Buffer.from(unsignedTx.serialize())

      // Check the signature
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign`)

      const signature = await signatureRequest
      console.log(signature)

      // @ts-ignore
      const js_signature = signedTx.auth.spendingCondition?.signature.signature

      console.log('js_signature ', js_signature)
      console.log('ledger-postSignHash: ', signature.postSignHash.toString('hex'))
      console.log('ledger-compact: ', signature.signatureCompact.toString('hex'))
      console.log('ledger-vrs', signature.signatureVRS.toString('hex'))
      console.log('ledger-DER: ', signature.signatureDER.toString('hex'))

      // @ts-ignore
      unsignedTx.auth.spendingCondition.signature = createMessageSignature(signature.signatureVRS.toString('hex'))
      //unsignedTx.auth.spendingCondition.signature.signature = signature.signatureVRS.toString('hex');

      console.log('unsignedTx serialized ', unsignedTx.serialize().toString('hex'))
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
      await sim.close()
    }
  })

  test.each(models)(`multisig`, async function (m) {
    const sim = new Zemu(m.path)
    const network = new StacksTestnet()
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())

      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST2XADQKC3EPZ62QTG5Q2RSPV64JG6KXCND0PHT7F')
      const amount = new BN(2500000)
      const fee = new BN(0)
      const nonce = new BN(0)
      const memo = 'multisig tx'

      const priv_key_signer0 = createStacksPrivateKey('219af15a772e3478a26bbe669b524e9e86c1aaa4c2ae640cd432a29431a4cb0101')
      const pub_key_signer0 = '03c00170321c5ce931d3201927ff6b1993c350f72af5483b9d75e8505ef10aed8c'
      const pubKeyStrings = [pub_key_signer0, devicePublicKey]

      const unsignedTx = await makeUnsignedSTXTokenTransfer({
        anchorMode: AnchorMode.Any,
        recipient: recipient,
        network,
        nonce: nonce,
        fee: fee,
        amount: amount,
        memo: memo,
        numSignatures: 2,
        publicKeys: pubKeyStrings,
      })
      const sigHashPreSign = makeSigHashPreSign(
        unsignedTx.signBegin(),
        // @ts-ignore
        unsignedTx.auth.authType,
        unsignedTx.auth.spendingCondition?.fee,
        unsignedTx.auth.spendingCondition?.nonce,
      ).toString()

      // Signer0 sign the transaction and append its post_sig_hash to the transaction buffer
      const signer0 = new TransactionSigner(unsignedTx)

      signer0.signOrigin(priv_key_signer0)

      // get signer0 post_sig_hash
      const postsig_hash_blob = Buffer.from(signer0.sigHash, 'hex')

      const serializeTx = unsignedTx.serialize().toString('hex')
      const publicKey = pubKeyfromPrivKey('219af15a772e3478a26bbe669b524e9e86c1aaa4c2ae640cd432a29431a4cb0101')
      let key_type
      if (isCompressed(publicKey)) {
        key_type = PubKeyEncoding.Compressed
      } else {
        key_type = PubKeyEncoding.Uncompressed
      }
      const blob3 = Buffer.alloc(1, key_type)
      // @ts-ignore
      const signature_signer0_hex = signer0.transaction.auth.spendingCondition.fields[0].contents.data
      const signer0_signature = Buffer.from(signature_signer0_hex, 'hex')

      const blob1 = Buffer.from(serializeTx, 'hex')
      // Pass a full transaction buffer, and the previous signer postsig_hash,  pubkey type
      // and vrs signature
      const arr = [blob1, postsig_hash_blob, blob3, signer0_signature]
      const blob = Buffer.concat(arr)

      // Signs the transaction that includes the previous signer post_sig_hash
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-multisigTest`)

      const signature = await signatureRequest
      console.log(signature)

      console.log('ledger-postSignHash: ', signature.postSignHash.toString('hex'))
      console.log('ledger-compact: ', signature.signatureCompact.toString('hex'))
      console.log('ledger-vrs', signature.signatureVRS.toString('hex'))
      console.log('ledger-DER: ', signature.signatureDER.toString('hex'))

      const signedTx = signer0.transaction
      // @ts-ignore
      signedTx.auth.spendingCondition.fields.push(createTransactionAuthField(signature.signatureVRS.toString('hex')))

      // Verifies the first signer signature using the preSigHash and signer0 data
      const ec = new EC('secp256k1')
      const signer0_signature_obj = {
        r: signature_signer0_hex.substr(2, 64),
        s: signature_signer0_hex.substr(66, 64),
      }
      // @ts-ignore
      const signatureOk = ec.verify(sigHashPreSign, signer0_signature_obj, pub_key_signer0, 'hex')
      expect(signatureOk).toEqual(true)

      // Verifies that the second signer's signature is ok

      // Construct the presig_hash from the prior_postsig_hash, authflag, fee and nonce
      const feeBytes = new BN(unsignedTx.auth.getFee()).toBuffer('le', 8)
      // @ts-ignore
      const nonceBytes = new BN(unsignedTx.auth.spendingCondition.nonce).toBuffer('le', 8)

      // @ts-ignore
      const presig_hash = [Buffer.from(signer0.sigHash, 'hex'), Buffer.alloc(1, unsignedTx.auth.authType), feeBytes, nonceBytes]

      const signer2_hash = Buffer.concat(presig_hash)
      const hash = sha512_256(signer2_hash)

      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.each(models)(`sign standard_contract_call_tx`, async function (m) {
    const sim = new Zemu(m.path)
    const network = new StacksTestnet()
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const my_key = '2e64805a5808a8a72df89b4b18d2451f8d5ab5224b4d8c7c36033aee4add3f27f'
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')
      const pubKeyStrings = [devicePublicKey]

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
      const fee = new BN(10)
      const nonce = new BN(0)
      const [contract_address, contract_name] = 'SP000000000000000000002Q6VF78.pox'.split('.')
      const txOptions = {
        anchorMode: AnchorMode.Any,
        contractAddress: contract_address,
        contractName: contract_name,
        functionName: 'stack-stx',
        functionArgs: [uintCV(20000), recipient, uintCV(2), uintCV(10)],
        network: network,
        fee: fee,
        nonce: nonce,
        publicKey: devicePublicKey,
      }

      const transaction = await makeUnsignedContractCall(txOptions)
      const serializeTx = transaction.serialize().toString('hex')

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_standard_contract_call_tx`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)
      // TODO: Verify signature
    } finally {
      await sim.close()
    }
  })

  test.each(models)(`sign_message`, async function (m) {
    const sim = new Zemu(m.path)
    const network = new StacksTestnet()
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())

      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const testPublicKey = pkResponse.publicKey.toString('hex')
      console.log('publicKey ', testPublicKey)

      // uses the provided privKey to derive a pubKey using stacks API
      // we expect the derived publicKey to be same as the ledger-app
      const expectedPublicKey = publicKeyToString(pubKeyfromPrivKey(senderKey))

      expect(testPublicKey).toEqual('02' + expectedPublicKey.slice(2, 2 + 32 * 2))

      const msg = "Hello World"

      // Check the signature
      const signatureRequest = app.sign_msg(path, msg)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_message`)

      const signature = await signatureRequest

      console.log(signature)
      expect(signature.returnCode).toEqual(0x9000)
      expect(signature.errorMessage).toEqual('No errors')

      //Verify signature
      const ec = new EC("secp256k1");
      const len = msg.length
      const data = "\x19Stacks Signed Message:\n" + `${len}` + msg
      console.log(data)
      const msgHash = sha512_256(data);
      const sig = signature.signatureVRS.toString('hex')
      const signature_obj = {
        r: sig.substr(2, 64),
        s: sig.substr(66, 64),
      }
      //@ts-ignore
      const signatureOk = ec.verify(msgHash, signature_obj, testPublicKey, "hex");
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close()
    }
  })

  test.each(models)(`sign call_with_string_args`, async function (m) {
    const sim = new Zemu(m.path)
    const network = new StacksTestnet()
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const my_key = '2e64805a5808a8a72df89b4b18d2451f8d5ab5224b4d8c7c36033aee4add3f27f'
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BlockstackApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')
      const pubKeyStrings = [devicePublicKey]

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
      const fee = new BN(10)
      const nonce = new BN(0)
      const [contract_address, contract_name] = 'SP000000000000000000002Q6VF78.pox'.split('.')
      const long_ascii_string = '%s{Lorem} ipsum dolor sit amet, consectetur adipiscing elit. Etiam quis bibendum mauris. Sed ac placerat ante. Donec sodales sapien id nulla convallis egestas'
      const txOptions = {
        anchorMode: AnchorMode.Any,
        contractAddress: contract_address,
        contractName: contract_name,
        functionName: 'stack-stx',
        functionArgs: [stringAsciiCV(long_ascii_string), uintCV(2), stringUtf8CV('Stacks balance, €: ')],
        network: network,
        fee: fee,
        nonce: nonce,
        publicKey: devicePublicKey,
      }

      const transaction = await makeUnsignedContractCall(txOptions)
      const serializeTx = transaction.serialize().toString('hex')
      console.log("serialized transaction length {}", serializeTx.length)

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-call_with_string_args`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)
      // TODO: Verify signature
    } finally {
      await sim.close()
    }
  })
})
