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

import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
import StacksApp from '@zondax/ledger-stacks'
import { APP_SEED, models, SIGNATURE_TEST_CASES } from './common'

import {
  AddressVersion,
  AuthType,
  makeUnsignedContractCall,
  makeUnsignedContractDeploy,
  sigHashPreSign,
  standardPrincipalCV,
  uintCV,
  Pc,
} from '@stacks/transactions'
import { STACKS_TESTNET } from '@stacks/network'
import { ec as EC } from 'elliptic'

const sha512_256 = require('js-sha512').sha512_256

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(180000)

describe('Sponsored', function () {
  test.concurrent.each(models)('sign sponsored_smart_contract_tx', async function (m) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get device public key
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      expect(pkResponse.returnCode).toEqual(0x9000)
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      // Create sponsored contract deployment
      const codeBody = `(define-data-var bar int 0)
(define-public (get-bar) (ok (var-get bar)))
(define-public (set-bar (x int) (y int))
  (begin (var-set bar (/ x y)) (ok (var-get bar))))`

      const transaction = await makeUnsignedContractDeploy({
        contractName: 'hello-world',
        codeBody: codeBody,
        publicKey: devicePublicKey,
        network: STACKS_TESTNET,
        fee: 0n,
        nonce: 0n,
        sponsored: true,
        clarityVersion: 2,
      })

      const blob = Buffer.from(transaction.serialize(), 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_sponsored_smart_contract_tx`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // Verify signature
      // For sponsored transactions, origin signer uses AuthType.Standard (0x04)
      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        AuthType.Standard,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)

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

  test.concurrent.each(models)('sign sponsored_contract_call_tx', async function (m) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get device public key
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      expect(pkResponse.returnCode).toEqual(0x9000)
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')

      const transaction = await makeUnsignedContractCall({
        contractAddress: 'ST000000000000000000002AMW42H',
        contractName: 'pox',
        functionName: 'stack-stx',
        functionArgs: [uintCV(20000), recipient, uintCV(2)],
        fee: 10n,
        nonce: 0n,
        publicKey: devicePublicKey,
        sponsored: true,
      })

      const blob = Buffer.from(transaction.serialize(), 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_sponsored_contract_call_tx`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // Verify signature
      // For sponsored transactions, origin signer uses AuthType.Standard (0x04)
      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        AuthType.Standard,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)

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

  test.concurrent.each(models)('sign sponsored_contract_call_tx_with_postconditions', async function (m) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      // Get device public key
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      expect(pkResponse.returnCode).toEqual(0x9000)
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')

      // Create post conditions using Pc builder
      const postConditionAddress = 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5'
      const postConditionAmount = 100n

      const postConditions = [
        Pc.principal(postConditionAddress).willSendGte(postConditionAmount).ft('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5.hello-world', 'stackaroos'),
        Pc.principal(postConditionAddress).willSendGte(postConditionAmount).ft('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5.hello-world', 'stackaroos'),
        Pc.principal(postConditionAddress).willSendGte(postConditionAmount).ft('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5.hello-world', 'stackaroos'),
      ]

      const transaction = await makeUnsignedContractCall({
        contractAddress: 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5',
        contractName: 'hello-world',
        functionName: 'send-stackaroos',
        functionArgs: [recipient],
        fee: 10n,
        nonce: 0n,
        publicKey: devicePublicKey,
        postConditions: postConditions,
        sponsored: true,
      })

      const blob = Buffer.from(transaction.serialize(), 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_sponsored_contract_call_tx_with_postconditions`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // Verify signature
      // For sponsored transactions, origin signer uses AuthType.Standard (0x04)
      const txSigHashPreSign = sigHashPreSign(
        transaction.signBegin(),
        AuthType.Standard,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      const presig_hash = Buffer.from(txSigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)

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

  SIGNATURE_TEST_CASES.forEach((testCase) => {
    test.concurrent.each(models)(testCase.name, async function (m) {
      const sim = new Zemu(m.path)
      const path = "m/44'/5757'/0'/0/0"

      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const app = new StacksApp(sim.getTransport())

        const signatureRequest = app.sign(path, testCase.blob)

        // Wait until we are not in the main menu
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)

        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${testCase.name.replace(/-/g, '_')}`)

        const signature = await signatureRequest
        console.log(signature)
        console.log('signatureVRS hex:', signature.signatureVRS.toString('hex'))

        expect(signature.returnCode).toEqual(0x9000)
        expect(signature.signatureVRS.toString('hex')).toEqual(testCase.expectedSignatureVRS)
      } finally {
        await sim.close()
      }
    })
  })
})
