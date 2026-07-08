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

import Zemu, { ButtonKind, DEFAULT_START_OPTIONS, isTouchDevice } from '@zondax/zemu'
import StacksApp, { LedgerError } from '@zondax/ledger-stacks'
import { AddressHashMode, AddressVersion, createMultiSigSpendingCondition } from '@stacks/transactions'
import { c32address } from 'c32check'
import { APP_SEED, models } from './common'

// c32 address version bytes for multisig (P2SH) addresses
const C32_VERSION_MAINNET_MULTISIG = 20 // SM...
const C32_VERSION_TESTNET_MULTISIG = 21 // SN...

// Two fixed, valid compressed secp256k1 cosigner public keys (not on this device)
const COSIGNER_0 = '03c00170321c5ce931d3201927ff6b1993c350f72af5483b9d75e8505ef10aed8c'
const COSIGNER_1 = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'

const DEVICE_PATH = "m/44'/5757'/0'/0/0"

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(180000)

// Ground truth: the multisig (P2SH) address for an ordered public-key set.
// createMultiSigSpendingCondition computes the Hash160 of the redeem script;
// c32address wraps it with the requested version byte.
function expectedMultisigAddress(version: number, numRequired: number, orderedPubKeysHex: string[]): string {
  const sc = createMultiSigSpendingCondition(AddressHashMode.P2SH, numRequired, orderedPubKeysHex, 0, 0)
  return c32address(version, sc.signer)
}

describe('Multisig address', function () {
  test.concurrent.each(models)('multisig addr 2-of-3 mainnet', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport() as any)

      // Device's own key for the path (so we can build the expected ordered set)
      const pk = await app.getAddressAndPubKey(DEVICE_PATH, AddressVersion.MainnetSingleSig)
      expect(pk.returnCode).toEqual(0x9000)
      const deviceKey = pk.publicKey.toString('hex')

      // 2-of-3, device key in the middle slot (index 1)
      const orderedKeys = [COSIGNER_0, deviceKey, COSIGNER_1]
      const expectedAddr = expectedMultisigAddress(C32_VERSION_MAINNET_MULTISIG, 2, orderedKeys)

      const response = await app.getMultisigAddressAndPubKey(DEVICE_PATH, C32_VERSION_MAINNET_MULTISIG as any, {
        numRequired: 2,
        deviceKeyIndex: 1,
        cosignerPublicKeys: [COSIGNER_0, COSIGNER_1], // ordered, device slot omitted
      })
      console.log('device multisig address:', response.address, 'expected:', expectedAddr)

      expect(response.returnCode).toEqual(0x9000)
      expect(response.publicKey.toString('hex')).toEqual(deviceKey)
      expect(response.address).toEqual(expectedAddr)
      expect(response.address.startsWith('SM')).toBe(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('multisig addr 1-of-2 testnet', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport() as any)

      const pk = await app.getAddressAndPubKey(DEVICE_PATH, AddressVersion.TestnetSingleSig)
      expect(pk.returnCode).toEqual(0x9000)
      const deviceKey = pk.publicKey.toString('hex')

      // 1-of-2, device key first (index 0)
      const orderedKeys = [deviceKey, COSIGNER_0]
      const expectedAddr = expectedMultisigAddress(C32_VERSION_TESTNET_MULTISIG, 1, orderedKeys)

      const response = await app.getMultisigAddressAndPubKey(DEVICE_PATH, C32_VERSION_TESTNET_MULTISIG as any, {
        numRequired: 1,
        deviceKeyIndex: 0,
        cosignerPublicKeys: [COSIGNER_0],
      })
      console.log('device multisig address:', response.address, 'expected:', expectedAddr)

      expect(response.returnCode).toEqual(0x9000)
      expect(response.publicKey.toString('hex')).toEqual(deviceKey)
      expect(response.address).toEqual(expectedAddr)
      expect(response.address.startsWith('SN')).toBe(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('multisig addr non-sequential (0x05) matches P2SH', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport() as any)

      const pk = await app.getAddressAndPubKey(DEVICE_PATH, AddressVersion.MainnetSingleSig)
      const deviceKey = pk.publicKey.toString('hex')

      const orderedKeys = [COSIGNER_0, deviceKey, COSIGNER_1]
      // Ground truth from the *non-sequential* spending condition. Its address is
      // identical to sequential P2SH for the same ordered key set, so the device
      // must accept hash mode 0x05 and return the same address.
      const sc = createMultiSigSpendingCondition(AddressHashMode.P2SHNonSequential, 2, orderedKeys, 0, 0)
      const expectedAddr = c32address(C32_VERSION_MAINNET_MULTISIG, sc.signer)

      const response = await app.getMultisigAddressAndPubKey(DEVICE_PATH, C32_VERSION_MAINNET_MULTISIG as any, {
        numRequired: 2,
        deviceKeyIndex: 1,
        cosignerPublicKeys: [COSIGNER_0, COSIGNER_1],
        hashMode: 0x05,
      })

      expect(response.returnCode).toEqual(0x9000)
      expect(response.address).toEqual(expectedAddr)
      // Sanity: same address as the sequential (0x01) mode for the same keys.
      expect(response.address).toEqual(expectedMultisigAddress(C32_VERSION_MAINNET_MULTISIG, 2, orderedKeys))
    } finally {
      await sim.close()
    }
  })

  // 14 fixed, valid compressed cosigner keys (compressed pubkeys for private keys 1..14).
  const COSIGNERS_14 = [
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
    '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
    '02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13',
    '022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4',
    '03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
    '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc',
    '03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe',
    '03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7',
    '03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb',
    '03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a',
    '03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8',
    '03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4',
    '02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e',
  ]

  test.concurrent.each(models)('multisig addr 8-of-15 mainnet (chunked transport)', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport() as any)

      const pk = await app.getAddressAndPubKey(DEVICE_PATH, AddressVersion.MainnetSingleSig)
      const deviceKey = pk.publicKey.toString('hex')

      // Device spliced into the 14 cosigners at index 3 -> 15 total keys, 8 required.
      const deviceIndex = 3
      const orderedKeys = [...COSIGNERS_14.slice(0, deviceIndex), deviceKey, ...COSIGNERS_14.slice(deviceIndex)]
      const expectedAddr = expectedMultisigAddress(C32_VERSION_MAINNET_MULTISIG, 8, orderedKeys)

      // 15 keys exceed one APDU, so this exercises the chunked transport path.
      const response = await app.getMultisigAddressAndPubKey(DEVICE_PATH, C32_VERSION_MAINNET_MULTISIG as any, {
        numRequired: 8,
        deviceKeyIndex: deviceIndex,
        cosignerPublicKeys: COSIGNERS_14,
      })
      console.log('15-key multisig address:', response.address, 'expected:', expectedAddr)

      expect(response.returnCode).toEqual(0x9000)
      expect(response.publicKey.toString('hex')).toEqual(deviceKey)
      expect(response.address).toEqual(expectedAddr)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('multisig addr rejects bad hash mode', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport() as any)

      // hash mode 0x03 (P2WSH) is not supported yet -> device must reject it
      const response = await app.getMultisigAddressAndPubKey(DEVICE_PATH, C32_VERSION_MAINNET_MULTISIG as any, {
        numRequired: 1,
        deviceKeyIndex: 0,
        cosignerPublicKeys: [COSIGNER_0],
        hashMode: 0x03,
      })

      expect(response.returnCode).toEqual(LedgerError.DataIsInvalid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show multisig addr 2-of-3', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.DynamicTapButton,
      })
      const app = new StacksApp(sim.getTransport() as any)

      const pk = await app.getAddressAndPubKey(DEVICE_PATH, AddressVersion.MainnetSingleSig)
      const deviceKey = pk.publicKey.toString('hex')

      const orderedKeys = [COSIGNER_0, deviceKey, COSIGNER_1]
      const expectedAddr = expectedMultisigAddress(C32_VERSION_MAINNET_MULTISIG, 2, orderedKeys)

      const respRequest = app.showMultisigAddressAndPubKey(DEVICE_PATH, C32_VERSION_MAINNET_MULTISIG as any, {
        numRequired: 2,
        deviceKeyIndex: 1,
        cosignerPublicKeys: [COSIGNER_0, COSIGNER_1],
      })

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_multisig_address`)

      const response = await respRequest
      expect(response.returnCode).toEqual(0x9000)
      expect(response.address).toEqual(expectedAddr)
    } finally {
      await sim.close()
    }
  })
})
