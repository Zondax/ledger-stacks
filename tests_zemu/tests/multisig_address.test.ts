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
