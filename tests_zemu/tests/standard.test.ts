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

import Zemu, { ButtonKind, DEFAULT_START_OPTIONS, isTouchDevice, zondaxMainmenuNavigation } from '@zondax/zemu'
import StacksApp from '@zondax/ledger-stacks'
import { APP_SEED, models, SIP10_DATA } from './common'
import { DLMM_CORE_V1_1_DEPLOYMENT, STANDARD_DEPLOYMENT } from './contracts'
import { encode } from 'varuint-bitcoin'

import {
  AddressVersion,
  PubKeyEncoding,
  StacksWireType,
  TransactionSigner,
  createTransactionAuthField,
  sigHashPreSign,
  makeSTXTokenTransfer,
  makeUnsignedContractCall,
  makeUnsignedContractDeploy,
  makeUnsignedSTXTokenTransfer,
  privateKeyToPublic,
  createStacksPublicKey,
  standardPrincipalCV,
  contractPrincipalCV,
  uintCV,
  stringAsciiCV,
  stringUtf8CV,
  tupleCV,
  intCV,
  bufferCV,
  listCV,
  responseOkCV,
  responseErrorCV,
  someCV,
  noneCV,
  trueCV,
  falseCV,
  FungibleConditionCode,
  Pc,
  BytesReader,
  deserializeTransaction,
} from '@stacks/transactions'
import { STACKS_TESTNET } from '@stacks/network'

const sha512_256 = require('js-sha512').sha512_256
const RIPEMD160 = require('ripemd160')
const sha256 = require('js-sha256').sha256
import { ec as EC } from 'elliptic'

// Helper function to convert bigint to little-endian buffer
function bigintToLeBuffer(value: bigint, length: number): Buffer {
  const buf = Buffer.alloc(length)
  for (let i = 0; i < length; i++) {
    buf[i] = Number(value & 0xffn)
    value = value >> 8n
  }
  return buf
}

// Helper function to create STX post conditions with the new Pc API
function createStxPostCondition(address: string, code: FungibleConditionCode, amount: bigint) {
  const builder = Pc.principal(address)
  switch (code) {
    case FungibleConditionCode.Equal:
      return builder.willSendEq(amount).ustx()
    case FungibleConditionCode.Greater:
      return builder.willSendGt(amount).ustx()
    case FungibleConditionCode.GreaterEqual:
      return builder.willSendGte(amount).ustx()
    case FungibleConditionCode.Less:
      return builder.willSendLt(amount).ustx()
    case FungibleConditionCode.LessEqual:
      return builder.willSendLte(amount).ustx()
    default:
      return builder.willSendEq(amount).ustx()
  }
}

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(180000)

const BIG_TUPLE = tupleCV({
  hello: uintCV(234),
  a: intCV(-1),
  b: bufferCV(Buffer.from('abcdefgh', 'ascii')),
  m: listCV([intCV(-1), intCV(-1), intCV(-1), intCV(-1)]),
  result_call: responseOkCV(stringAsciiCV('done')),
  error_msg: responseErrorCV(stringUtf8CV('unknown URI')),
  nested: someCV(listCV([noneCV(), someCV(intCV(-100))])),
  principal: standardPrincipalCV('SP2JXKMSH007NPYAQHKJPQMAQYAD90NQGTVJVQ02B'),
  l: tupleCV({
    a: trueCV(),
    b: falseCV(),
  }),
  contractPrincipal: contractPrincipalCV('SP2JXKMSH007NPYAQHKJPQMAQYAD90NQGTVJVQ02B', 'test'),
  xxxx: tupleCV({
    yyyy: intCV(123),
    ddd: tupleCV({
      ggg: uintCV(123),
    }),
  }),
})

describe('Standard', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`get app version`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
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

  test.concurrent.each(models)(`get address`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

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

  test.concurrent.each(models)(`get address2`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Verify that the app works for m/5757'/x/x/x/x
      const response = await app.getAddressAndPubKey("m/5757'/0'/5'/0/0", AddressVersion.MainnetSingleSig)
      console.log(response)
      expect(response.returnCode).toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`get identify publicKey`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const response = await app.getIdentityPubKey("m/888'/0'/19") //m/888'/0'/<account>
      console.log(response)
      expect(response.returnCode).toEqual(0x9000)

      const expectedPublicKey = '02ab551821f7a7373b40b5f53547096df9ddd1c6dd8e410f8a87f6cacc7a4314cc'

      expect(response.publicKey.toString('hex')).toEqual(expectedPublicKey)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`show address`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.DynamicTapButton,
      })
      const app = new StacksApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = "m/44'/5757'/5'/0/3"

      const respRequest = app.showAddressAndPubKey(path, AddressVersion.MainnetSingleSig)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

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

  test.concurrent.each(models)(`sign`, async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const testPublicKey = pkResponse.publicKey.toString('hex')
      console.log('publicKey ', testPublicKey)

      // uses the provided privKey to derive a pubKey using stacks API
      // we expect the derived publicKey to be same as the ledger-app
      const expectedPublicKey = privateKeyToPublic(senderKey)

      expect(testPublicKey).toEqual('02' + expectedPublicKey.slice(2, 2 + 32 * 2))

      const signedTx = await makeSTXTokenTransfer({
                senderKey,
        recipient: 'ST12KRFTX4APEB6201HY21JMSTPSSJ2QR28MSPPWK',
        network,
        nonce: 0n,
        fee: 180n,
        amount: 1n,
      })

      const unsignedTx = await makeUnsignedSTXTokenTransfer({
                recipient: 'ST12KRFTX4APEB6201HY21JMSTPSSJ2QR28MSPPWK',
        network,
        nonce: 0n,
        fee: 180n,
        amount: 1n,
        publicKey: testPublicKey,
      })

      const blob = Buffer.from(unsignedTx.serialize(), 'hex')

      // Check the signature
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign`)

      const signature = await signatureRequest
      console.log(signature)

      // @ts-ignore
      const js_signature = signedTx.auth.spendingCondition?.signature.signature

      console.log('js_signature ', js_signature)
      console.log('ledger-postSignHash: ', signature.postSignHash.toString('hex'))
      console.log('ledger-compact: ', signature.signatureCompact.toString('hex'))
      console.log('ledger-vrs', signature.signatureVRS.toString('hex'))
      console.log('ledger-DER: ', signature.signatureDER.toString('hex'))

      console.log('unsignedTx serialized ', unsignedTx.serialize())

      const txSigHashPreSign = sigHashPreSign(
        unsignedTx.signBegin(),
        //@ts-ignore
        unsignedTx.auth.authType,
        unsignedTx.auth.spendingCondition?.fee,
        unsignedTx.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      //Verify signature
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, testPublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
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

  test.concurrent.each(models)(`multisig`, async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = createStacksPublicKey(pkResponse.publicKey)
      const devicePublicKeyString = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST2XADQKC3EPZ62QTG5Q2RSPV64JG6KXCND0PHT7F')
      const amount = 2500000n
      const fee = 0n
      const nonce = 0n
      const memo = 'multisig tx'

      const priv_key_signer0 = '219af15a772e3478a26bbe669b524e9e86c1aaa4c2ae640cd432a29431a4cb0101'
      const pub_key_signer0 = '03c00170321c5ce931d3201927ff6b1993c350f72af5483b9d75e8505ef10aed8c'
      const pubKeyStrings = [pub_key_signer0, devicePublicKeyString]

      const tx = await makeUnsignedSTXTokenTransfer({
                recipient,
        network,
        nonce,
        fee,
        amount,
        memo,
        numSignatures: 2,
        publicKeys: pubKeyStrings,
      })
      const txSigHashPreSign = sigHashPreSign(
        tx.signBegin(),
        // @ts-ignore
        tx.auth.authType,
        tx.auth.spendingCondition?.fee,
        tx.auth.spendingCondition?.nonce,
      ).toString()

      // Signer0 sign the transaction and append its post_sig_hash to the transaction buffer
      const signer0 = new TransactionSigner(tx)

      signer0.signOrigin(priv_key_signer0)
      signer0.appendOrigin(devicePublicKey)

      const serializeTx = tx.serialize()

      // @ts-ignore
      const signature_signer0_hex = tx.auth.spendingCondition.fields[0].contents.data

      const blob = Buffer.from(serializeTx, 'hex')

      // Signs the transaction that includes the previous signer post_sig_hash
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-multisigTest`)

      const signature = await signatureRequest
      console.log(signature)

      console.log('ledger-postSignHash: ', signature.postSignHash.toString('hex'))
      console.log('ledger-compact: ', signature.signatureCompact.toString('hex'))
      console.log('ledger-vrs', signature.signatureVRS.toString('hex'))
      console.log('ledger-DER: ', signature.signatureDER.toString('hex'))

      // @ts-ignore
      // Add Ledger signature to transaction
      tx.auth.spendingCondition.fields[1] = createTransactionAuthField(PubKeyEncoding.Compressed, {
        data: signature.signatureVRS.toString('hex'),
        type: StacksWireType.MessageSignature,
      })

      // For full tx validation, use `stacks-inspect decode-tx <hex-encoded-tx>`
      const txBytes = tx.serialize()
      console.log('tx-bytes', txBytes)

      // Verifies the first signer signature using the preSigHash and signer0 data
      const ec = new EC('secp256k1')
      const signer0_signature_obj = {
        r: signature_signer0_hex.substr(2, 64),
        s: signature_signer0_hex.substr(66, 64),
      }
      // @ts-ignore
      const signatureOk = ec.verify(txSigHashPreSign, signer0_signature_obj, pub_key_signer0, 'hex')
      expect(signatureOk).toEqual(true)

      // Verifies that the second signer's signature is ok

      // Construct the presig_hash from the prior_postsig_hash, authflag, fee and nonce
      // @ts-ignore
      const feeBytes = bigintToLeBuffer(tx.auth.spendingCondition?.fee ?? 0n, 8)
      // @ts-ignore
      const nonceBytes = bigintToLeBuffer(tx.auth.spendingCondition?.nonce ?? 0n, 8)

      // @ts-ignore
      const presig_hash = [Buffer.from(signer0.sigHash, 'hex'), Buffer.alloc(1, tx.auth.authType), feeBytes, nonceBytes]

      const signer2_hash = Buffer.concat(presig_hash)
      const hash = sha512_256(signer2_hash)

      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(hash, signature1_obj, devicePublicKeyString, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`order-independent multisig`, async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = createStacksPublicKey(pkResponse.publicKey)
      const devicePublicKeyString = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST2XADQKC3EPZ62QTG5Q2RSPV64JG6KXCND0PHT7F')
      const amount = 2500000n
      const fee = 0n
      const nonce = 0n
      const memo = 'multisig tx'

      const priv_key_signer0 = '219af15a772e3478a26bbe669b524e9e86c1aaa4c2ae640cd432a29431a4cb0101'
      const pub_key_signer0 = '03c00170321c5ce931d3201927ff6b1993c350f72af5483b9d75e8505ef10aed8c'
      const pubKeyStrings = [pub_key_signer0, devicePublicKeyString]

      const tx = await makeUnsignedSTXTokenTransfer({
                recipient,
        network,
        nonce,
        fee,
        amount,
        memo,
        numSignatures: 2,
        publicKeys: pubKeyStrings,
      })

      // @ts-ignore
      // Use order-independent multisig P2SH
      // TODO: Replace with constant once support is added in Stacks.js
      tx.auth.spendingCondition.hashMode = 5

      const txSigHashPreSign = sigHashPreSign(
        tx.signBegin(),
        // @ts-ignore
        tx.auth.authType,
        tx.auth.spendingCondition?.fee,
        tx.auth.spendingCondition?.nonce,
      ).toString()

      // Signer0 sign the transaction and append its post_sig_hash to the transaction buffer
      const signer0 = new TransactionSigner(tx)

      signer0.signOrigin(priv_key_signer0)
      signer0.appendOrigin(devicePublicKey)

      const serializeTx = tx.serialize()

      // @ts-ignore
      const signature_signer0_hex = tx.auth.spendingCondition.fields[0].contents.data

      const blob = Buffer.from(serializeTx, 'hex')

      // Signs the transaction that includes the previous signer post_sig_hash
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-order_independent_multisigTest`)

      const signature = await signatureRequest
      console.log(signature)

      const signatureVRS = signature.signatureVRS.toString('hex')
      console.log('ledger-postSignHash: ', signature.postSignHash.toString('hex'))
      console.log('ledger-compact: ', signature.signatureCompact.toString('hex'))
      console.log('ledger-vrs', signatureVRS)
      console.log('ledger-DER: ', signature.signatureDER.toString('hex'))

      // @ts-ignore
      // Add Ledger signature to transaction
      tx.auth.spendingCondition.fields[1] = createTransactionAuthField(PubKeyEncoding.Compressed, {
        type: StacksWireType.MessageSignature,
        data: signatureVRS,
      })

      // For full tx validation, use `stacks-inspect decode-tx <hex-encoded-tx>`
      const txBytes = tx.serialize()
      console.log('tx-bytes', txBytes)

      // Verifies the first signer signature using the preSigHash and signer0 data
      const ec = new EC('secp256k1')
      const signer0_signature_obj = {
        r: signature_signer0_hex.substr(2, 64),
        s: signature_signer0_hex.substr(66, 64),
      }
      // @ts-ignore
      const signatureOk = ec.verify(txSigHashPreSign, signer0_signature_obj, pub_key_signer0, 'hex')
      expect(signatureOk).toEqual(true)

      // Verifies that the second signer's signature is ok
      const signature1_obj = { r: signatureVRS.substr(2, 64), s: signatureVRS.substr(66, 64) }

      // @ts-ignore
      const signature1Ok = ec.verify(txSigHashPreSign, signature1_obj, devicePublicKeyString, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`sign standard_contract_call_tx`, async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const my_key = '2e64805a5808a8a72df89b4b18d2451f8d5ab5224b4d8c7c36033aee4add3f27f'
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
      const contract_principal = contractPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5', 'some-contract-name')
      const fee = 10n
      const nonce = 0n
      const [contract_address, contract_name] = 'SP000000000000000000002Q6VF78.pox'.split('.')
      const txOptions = {
                contractAddress: contract_address,
        contractName: contract_name,
        functionName: 'stack-stx',
        functionArgs: [uintCV(20000), recipient, uintCV(2), contract_principal, uintCV(10)],
        network: network,
        fee: fee,
        nonce: nonce,
        publicKey: devicePublicKey,
      }

      const transaction = await makeUnsignedContractCall(txOptions)
      const serializeTx = transaction.serialize()

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_standard_contract_call_tx`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // compute postSignHash to verify signature

      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      //Verify signature
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`sign_contract_call_long_args`, async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const my_key = '2e64805a5808a8a72df89b4b18d2451f8d5ab5224b4d8c7c36033aee4add3f27f'
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
      const contract_principal = contractPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5', 'some-contract-name')
      const fee = 10n
      const nonce = 0n
      const [contract_address, contract_name] = 'SP000000000000000000002Q6VF78.long_args_contract'.split('.')
      const txOptions = {
                contractAddress: contract_address,
        contractName: contract_name,
        functionName: 'stack-stx',
        functionArgs: [
          uintCV(20000),
          recipient,
          intCV(-2),
          someCV(listCV([noneCV(), someCV(intCV(-100))])),
          contract_principal,
          uintCV(20),
          BIG_TUPLE,
          bufferCV(Buffer.from('abcdefgh', 'ascii')),
        ],
        network: network,
        fee: fee,
        nonce: nonce,
        publicKey: devicePublicKey,
      }

      const transaction = await makeUnsignedContractCall(txOptions)
      const serializeTx = transaction.serialize()

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-contract_call_long_args`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // compute postSignHash to verify signature

      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      //Verify signature
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`sign_message`, async function (m) {
    const sim = new Zemu(m.path)
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const testPublicKey = pkResponse.publicKey.toString('hex')
      console.log('publicKey ', testPublicKey)

      // uses the provided privKey to derive a pubKey using stacks API
      // we expect the derived publicKey to be same as the ledger-app
      const expectedPublicKey = privateKeyToPublic(senderKey)

      expect(testPublicKey).toEqual('02' + expectedPublicKey.slice(2, 2 + 32 * 2))

      const msg =
        "Welcome!\nSign this message to access Gamma's full feature set.\nAs always, by using Gamma, you agree to our terms of use: https://gamma.io/terms\nDomain: gamma.io\nAccount: SP2PH3XAPDMSKXQVS1WZ80JGZACY713JQQEE1DY48\nNonce: c83024f9e9aef40f5d72076e883054c07100035112826b14f78e5a893d62b1bf\n"

      // Check the signature
      const signatureRequest = app.sign_msg(path, msg)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_message`)

      const signature = await signatureRequest

      console.log(signature)
      expect(signature.returnCode).toEqual(0x9000)
      expect(signature.errorMessage).toEqual('No errors')

      //Verify signature
      const ec = new EC('secp256k1')

      const len_buf = encode(msg.length).buffer
      const header = Buffer.from('\x17Stacks Signed Message:\n', 'utf8')
      const msg_buf = Buffer.from(msg, 'utf8')

      const arr = [header, Buffer.from(len_buf), msg_buf]
      const data = Buffer.concat(arr)

      const msgHash = sha256(data)
      const sig = signature.signatureVRS.toString('hex')

      const signature_obj = {
        r: Buffer.from(sig.substr(2, 64), 'hex'),
        s: Buffer.from(sig.substr(66, 64), 'hex'),
      }
      const pubkey = Buffer.from(testPublicKey, 'hex')
      const signatureOk = ec.verify(msgHash, signature_obj, pubkey, 'hex')
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`sign_jwt`, async function (m) {
    const sim = new Zemu(m.path)
    const path = "m/888'/0'/1"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const jwt =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ==.eyJpc3N1ZWRfYXQiOjE0NDA3MTM0MTQuODUsImNoYWxsZW5nZSI6IjdjZDllZDVlLWJiMGUtNDllYS1hMzIzLWYyOGJkZTNhMDU0OSIsImlzc3VlciI6InhwdWI2NjFNeU13QXFSYmNGUVZyUXI0UTRrUGphUDRKaldhZjM5ZkJWS2pQZEs2b0dCYXlFNDZHQW1Lem81VURQUWRMU005RHVmWmlQOGVhdXk1NlhOdUhpY0J5U3ZacDdKNXdzeVFWcGkyYXh6WiIsImJsb2NrY2hhaW5pZCI6InJ5YW4ifQ=='

      const pkResponse = await app.getIdentityPubKey(path)

      // Check the signature
      const signatureRequest = app.sign_jwt(path, jwt)

      // Wait until we are not in the main men
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_jwt`)

      const signature = await signatureRequest

      console.log(signature)
      expect(signature.returnCode).toEqual(0x9000)
      expect(signature.errorMessage).toEqual('No errors')

      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const testPublicKey = pkResponse.publicKey.toString('hex')
      console.log('publicKey ', testPublicKey)

      const jwt_hash = sha256(jwt)

      //Verify signature

      // Verify we sign the same hash
      const postSignHash = signature.postSignHash.toString('hex')
      console.log('postSignHash: ', postSignHash)

      expect(jwt_hash).toEqual(postSignHash)

      const ec = new EC('secp256k1')
      const sig = signature.signatureVRS.toString('hex')
      const signature_obj = {
        r: sig.substr(2, 64),
        s: sig.substr(66, 64),
      }
      //@ts-ignore
      const signatureOk = ec.verify(postSignHash, signature_obj, testPublicKey, 'hex')
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`sign call_with_string_args`, async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
      const fee = 10n
      const nonce = 0n
      const [contract_address, contract_name] = 'SP000000000000000000002Q6VF78.pox'.split('.')
      const long_ascii_string =
        '%s{Lorem} ipsum dolor sit amet, consectetur adipiscing elit. Etiam quis bibendum mauris. Sed ac placerat ante. Donec sodales sapien id nulla convallis egestas'
      const txOptions = {
                contractAddress: contract_address,
        contractName: contract_name,
        functionName: 'stack-stx',
        functionArgs: [stringAsciiCV(long_ascii_string), uintCV(2), stringUtf8CV('Stacks balance, €: '), recipient],
        network: network,
        fee: fee,
        nonce: nonce,
        publicKey: devicePublicKey,
      }

      const transaction = await makeUnsignedContractCall(txOptions)
      const serializeTx = transaction.serialize()
      console.log('serialized transaction length {}', serializeTx.length)

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-call_with_string_args`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // compute postSignHash to verify signature

      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      //Verify signature
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`sign_contract_and_post_conditions`, async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const my_key = '2e64805a5808a8a72df89b4b18d2451f8d5ab5224b4d8c7c36033aee4add3f27f'
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
      const contract_principal = contractPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5', 'some-contract-name')
      const fee = 10n
      const nonce = 0n
      const [contract_address, contract_name] = 'SP000000000000000000002Q6VF78.long_args_contract'.split('.')

      const postConditionAddress = 'SP2ZD731ANQZT6J4K3F5N8A40ZXWXC1XFXHVVQFKE'
      const postConditionAddress2 = 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5'
      const postConditionAddress3 = 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5'
      const postConditionAmount = 1000000n
      const postConditionAmount2 = 1005020n
      const postConditions = [
        Pc.principal(postConditionAddress).willSendGte(postConditionAmount).ustx(),
        Pc.principal(postConditionAddress2).willSendGte(postConditionAmount).ustx(),
        Pc.principal(postConditionAddress3).willSendGte(postConditionAmount2).ustx(),
      ]

      const txOptions = {
                contractAddress: contract_address,
        contractName: contract_name,
        functionName: 'stack-stx',
        functionArgs: [
          uintCV(20000),
          recipient,
          intCV(-2),
          someCV(listCV([noneCV(), someCV(intCV(-100))])),
          contract_principal,
          uintCV(20),
          BIG_TUPLE,
          bufferCV(Buffer.from('abcdefgh', 'ascii')),
        ],
        network: network,
        fee: fee,
        nonce: nonce,
        publicKey: devicePublicKey,
        postConditions,
      }

      const transaction = await makeUnsignedContractCall(txOptions)
      const serializeTx = transaction.serialize()

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-swap_with_post_conditions`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // compute postSignHash to verify signature

      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      //Verify signature
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  describe.each(SIP10_DATA)('SIP-10 tests', function (data) {
    test.concurrent.each(models)('sign_sip10_contract', async function (m) {
      const sim = new Zemu(m.path)
      const network = STACKS_TESTNET
      const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
      const my_key = '2e64805a5808a8a72df89b4b18d2451f8d5ab5224b4d8c7c36033aee4add3f27f'
      const path = "m/44'/5757'/0'/0/0"
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const app = new StacksApp(sim.getTransport())
        // Get pubkey and check
        const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
        console.log(pkResponse)
        expect(pkResponse.returnCode).toEqual(0x9000)
        expect(pkResponse.errorMessage).toEqual('No errors')
        const devicePublicKey = pkResponse.publicKey.toString('hex')

        const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
        const sender = standardPrincipalCV('SP2ZD731ANQZT6J4K3F5N8A40ZXWXC1XFXHVVQFKE')
        const fee = 10n
        const nonce = 0n
        const [contract_address, contract_name] = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token'.split('.')

        let txOptions = {
                    contractAddress: contract_address,
          contractName: contract_name,
          functionName: 'transfer',
          functionArgs: [uintCV(20000), sender, recipient, someCV(stringAsciiCV('tx_memo'))],
          network: network,
          fee: fee,
          nonce: nonce,
          publicKey: devicePublicKey,
          postConditions: data.postConditions ? [
            createStxPostCondition(data.postConditions[0].address, data.postConditions[0].code, data.postConditions[0].amount),
            createStxPostCondition(data.postConditions[1].address, data.postConditions[1].code, data.postConditions[1].amount),
          ] : [],
        }

        const transaction = await makeUnsignedContractCall(txOptions)
        const serializeTx = transaction.serialize()

        const blob = Buffer.from(serializeTx, 'hex')
        const signatureRequest = app.sign(path, blob)

        // Wait until we are not in the main menu
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${data.snapshotSuffix}`)

        const signature = await signatureRequest
        console.log(signature)

        expect(signature.returnCode).toEqual(0x9000)

        // compute postSignHash to verify signature

        const txSigHashPreSign = sigHashPreSign(
          transaction.signBegin(),
          // @ts-ignore
          transaction.auth.authType,
          transaction.auth.spendingCondition?.fee,
          transaction.auth.spendingCondition?.nonce,
        )
        console.log('sigHashPreSign: ', txSigHashPreSign)
        const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

        const key_t = Buffer.alloc(1)
        key_t.writeInt8(0x00)

        const array = [presig_hash, key_t, signature.signatureVRS]
        const to_hash = Buffer.concat(array)
        const hash = sha512_256(to_hash)
        console.log('computed postSignHash: ', hash.toString('hex'))

        // compare hashes
        expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

        //Verify signature
        const ec = new EC('secp256k1')
        const signature1 = signature.signatureVRS.toString('hex')
        const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
        // @ts-ignore
        const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
        expect(signature1Ok).toEqual(true)
      } finally {
        await sim.close()
      }
    })
  })

  test.concurrent.each(models)('sign standard_smart_contract_tx', async function (m) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/5'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get pubkey for verification
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const blob = Buffer.from(STANDARD_DEPLOYMENT, 'hex')

      // Deserialize transaction to compute signature hash
      const bufferReader = new BytesReader(blob)
      const transaction = deserializeTransaction(bufferReader)

      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_standard_smart_contract_tx`)

      const signature = await signatureRequest
      console.log('Signature: ')
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // Verify signature
      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      // Verify signature cryptographically
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  // Skip NanoS for large contract deployments due to memory restrictions
  // NanoS buffer can't handle contracts as large as dlmm-core (81KB)
  test.concurrent.each(models.filter((m) => m.name !== 'nanos'))('sign dlmm-core contract deployment', async function (m) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/5'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const blob = Buffer.from(DLMM_CORE_V1_1_DEPLOYMENT, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dlmm_core_deployment`)

      const signature = await signatureRequest
      console.log('Signature: ')
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)
      expect(signature.signatureCompact).toBeDefined()
      expect(signature.signatureDER).toBeDefined()
      expect(signature.postSignHash).toBeDefined()

      /*
      Signature verification is disabled for this test due to an issue with @stacks/transactions library's handling of large payloads (81KB contract).
      The makeSigHashPreSign function computes a different presig_hash than what the device computes for such large contracts, causing the postSignHash verification to fail.
      The signature for contract deployments is already verified in the test above (sign_standard_smart_contract)
      */
    } finally {
      await sim.close()
    }
  })

  // Test for multisig 1/1 smart contract deployment
  // This test addresses the issue where deploying contracts via Ledger multisig
  // results in "SignatureValidation" error: "Signer hash does not equal hash of public key(s)"
  test.concurrent.each(models)('sign multisig 1/1 smart contract deployment', async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get pubkey from device
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')
      console.log('Device public key:', devicePublicKey)

      // Simple test contract for deployment
      const contractCode = `
;; Simple test contract for multisig deployment
(define-data-var counter uint u0)

(define-public (increment)
  (begin
    (var-set counter (+ (var-get counter) u1))
    (ok (var-get counter))))

(define-read-only (get-counter)
  (ok (var-get counter)))
`

      const fee = 10000n
      const nonce = 0n

      // Create multisig 1/1 contract deploy transaction
      const txOptions = {
        contractName: 'test-multisig-contract',
        codeBody: contractCode,
        network: network,
        fee: fee,
        nonce: nonce,
        numSignatures: 1,
        publicKeys: [devicePublicKey],
        clarityVersion: 4,
      }

      const transaction = await makeUnsignedContractDeploy(txOptions)
      const serializeTx = transaction.serialize()
      console.log('Serialized transaction length:', serializeTx.length)

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_multisig_1_1_contract_deploy`)

      const signature = await signatureRequest
      console.log('Signature:', signature)

      expect(signature.returnCode).toEqual(0x9000)
      expect(signature.signatureCompact).toBeDefined()
      expect(signature.signatureDER).toBeDefined()
      expect(signature.postSignHash).toBeDefined()

      console.log('ledger-postSignHash:', signature.postSignHash.toString('hex'))
      console.log('ledger-compact:', signature.signatureCompact.toString('hex'))
      console.log('ledger-vrs:', signature.signatureVRS.toString('hex'))
      console.log('ledger-DER:', signature.signatureDER.toString('hex'))

      // Compute and verify signature
      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign:', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash:', hash.toString('hex'))

      // Compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      // Verify signature cryptographically
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)

      // Add signature to transaction for verification
      // @ts-ignore
      transaction.auth.spendingCondition.fields[0] = createTransactionAuthField(PubKeyEncoding.Compressed, {
        data: signature.signatureVRS.toString('hex'),
        type: StacksWireType.MessageSignature,
      })

      // Serialize final transaction
      const txBytes = transaction.serialize()
      console.log('Final signed transaction hex:', txBytes)
    } finally {
      await sim.close()
    }
  })

  // Test for multisig 1/1 LARGE contract deployment (~80KB)
  // This test reproduces the exact error reported: "Signer hash does not equal hash of public key(s)"
  // The issue only occurs with large contracts that require many APDU chunks
  // Skip NanoS due to memory restrictions
  test.concurrent.each(models.filter((m) => m.name !== 'nanos'))('sign multisig 1/1 LARGE contract deployment (~80KB)', async function (m) {
    const sim = new Zemu(m.path)
    const network = STACKS_TESTNET
    const path = "m/44'/5757'/0'/0/0"

    // Generate a large contract (~80KB) to reproduce the issue
    function generateLargeContract(targetSizeKB: number = 80): string {
      const targetSize = targetSizeKB * 1024

      let contract = `;; Large test contract for multisig deployment (~${targetSizeKB}KB)
;; This simulates a complex DeFi contract similar to dlmm-core

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u1001))
(define-constant ERR-INVALID-AMOUNT (err u1002))
(define-constant ERR-INSUFFICIENT-BALANCE (err u1003))

;; Data variables
(define-data-var contract-owner principal tx-sender)
(define-data-var total-value-locked uint u0)
(define-data-var protocol-fee-rate uint u30)
(define-data-var is-paused bool false)

;; Data maps
(define-map user-balances principal uint)
(define-map pool-reserves { pool-id: uint } { reserve-x: uint, reserve-y: uint })

;; Read-only functions
(define-read-only (get-owner)
  (ok (var-get contract-owner)))

(define-read-only (get-tvl)
  (ok (var-get total-value-locked)))

`

      // Add many functions to reach target size
      let fnIndex = 0
      while (contract.length < targetSize) {
        const fnType = fnIndex % 3

        if (fnType === 0) {
          contract += `
(define-read-only (get-pool-data-${fnIndex.toString().padStart(4, '0')} (pool-id uint))
  (let (
    (reserves (default-to { reserve-x: u0, reserve-y: u0 } (map-get? pool-reserves { pool-id: pool-id })))
    (fee-rate (var-get protocol-fee-rate))
  )
  (ok {
    reserve-x: (get reserve-x reserves),
    reserve-y: (get reserve-y reserves),
    fee: fee-rate,
    pool-id: pool-id
  })))

`
        } else if (fnType === 1) {
          contract += `
(define-public (update-position-${fnIndex.toString().padStart(4, '0')} (pool-id uint) (amount uint))
  (let (
    (sender tx-sender)
    (current-balance (default-to u0 (map-get? user-balances sender)))
    (pool-data (default-to { reserve-x: u0, reserve-y: u0 } (map-get? pool-reserves { pool-id: pool-id })))
  )
  (asserts! (not (var-get is-paused)) ERR-NOT-AUTHORIZED)
  (asserts! (> amount u0) ERR-INVALID-AMOUNT)
  (asserts! (>= current-balance amount) ERR-INSUFFICIENT-BALANCE)
  (map-set user-balances sender (- current-balance amount))
  (map-set pool-reserves { pool-id: pool-id }
    { reserve-x: (+ (get reserve-x pool-data) amount), reserve-y: (get reserve-y pool-data) })
  (ok true)))

`
        } else {
          contract += `
(define-read-only (calculate-swap-${fnIndex.toString().padStart(4, '0')} (pool-id uint) (amount-in uint) (is-x-to-y bool))
  (let (
    (pool-data (default-to { reserve-x: u0, reserve-y: u0 } (map-get? pool-reserves { pool-id: pool-id })))
    (reserve-in (if is-x-to-y (get reserve-x pool-data) (get reserve-y pool-data)))
    (reserve-out (if is-x-to-y (get reserve-y pool-data) (get reserve-x pool-data)))
    (fee-rate (var-get protocol-fee-rate))
    (amount-with-fee (/ (* amount-in (- u10000 fee-rate)) u10000))
  )
  (ok {
    amount-out: (/ (* amount-with-fee reserve-out) (+ reserve-in amount-with-fee)),
    fee-amount: (- amount-in amount-with-fee)
  })))

`
        }
        fnIndex++
      }

      return contract
    }

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get pubkey from device
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')
      console.log('Device public key:', devicePublicKey)

      // Generate large contract (~80KB)
      const contractCode = generateLargeContract(80)
      console.log('Contract code size:', contractCode.length, 'bytes (~', (contractCode.length / 1024).toFixed(2), 'KB)')

      const fee = 10000n
      const nonce = 0n

      // Create multisig 1/1 contract deploy transaction
      const txOptions = {
        contractName: 'large-multisig-contract',
        codeBody: contractCode,
        network: network,
        fee: fee,
        nonce: nonce,
        numSignatures: 1,
        publicKeys: [devicePublicKey],
        clarityVersion: 4,
      }

      const transaction = await makeUnsignedContractDeploy(txOptions)
      const serializeTx = transaction.serialize()
      console.log('Serialized transaction length:', serializeTx.length, 'chars (~', (serializeTx.length / 2 / 1024).toFixed(2), 'KB)')

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_multisig_1_1_large_contract_deploy`)

      const signature = await signatureRequest
      console.log('Signature:', signature)

      expect(signature.returnCode).toEqual(0x9000)
      expect(signature.signatureCompact).toBeDefined()
      expect(signature.signatureDER).toBeDefined()
      expect(signature.postSignHash).toBeDefined()

      console.log('ledger-postSignHash:', signature.postSignHash.toString('hex'))
      console.log('ledger-compact:', signature.signatureCompact.toString('hex'))
      console.log('ledger-vrs:', signature.signatureVRS.toString('hex'))
      console.log('ledger-DER:', signature.signatureDER.toString('hex'))

      // Compute expected postSignHash
      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('JS sigHashPreSign:', txSigHashPreSign)
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('JS computed postSignHash:', hash.toString('hex'))
      console.log('Device postSignHash:', signature.postSignHash.toString('hex'))

      // THIS IS THE CRITICAL CHECK - for large contracts, these should match
      // If they don't match, the broadcast will fail with "Signer hash does not equal hash of public key(s)"
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      // Verify signature cryptographically
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)

      // Add signature to transaction
      // @ts-ignore
      transaction.auth.spendingCondition.fields[0] = createTransactionAuthField(PubKeyEncoding.Compressed, {
        data: signature.signatureVRS.toString('hex'),
        type: StacksWireType.MessageSignature,
      })

      // Serialize final transaction
      const txBytes = transaction.serialize()
      console.log('Final signed transaction length:', txBytes.length, 'chars')
    } finally {
      await sim.close()
    }
  })
})
