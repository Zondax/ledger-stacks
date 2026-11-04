/** ******************************************************************************
 *  (c) 2026 Zondax AG
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

/**
 * Regressions for the Quarkslab review 26-10-3001-REP of the v0.27.1 release.
 */

import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
import StacksApp from '@zondax/ledger-stacks'
import { AddressVersion, makeUnsignedContractCall, stringAsciiCV } from '@stacks/transactions'
import { STACKS_TESTNET } from '@stacks/network'
import { APP_SEED, models } from './common'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(180000)

const CLA = 0x09
const INS_SIGN = 0x02
const INS_GET_AUTH_PUBKEY = 0x03
const INS_SIGN_JWT = 0x04
const INS_GET_ADDR_MULTISIG = 0x07
const P1_INIT = 0x00
const P1_LAST = 0x02

const SW_OK = 0x9000
const SW_DATA_INVALID = 0x6984
const SW_TX_NOT_INITIALIZED = 0x6987

const PATH = "m/44'/5757'/0'/0/0"

function serializePath(path: string): Buffer {
  const parts = path.split('/').slice(1)
  const buf = Buffer.alloc(parts.length * 4)
  parts.forEach((part, i) => {
    const hardened = part.endsWith("'")
    const index = Number(hardened ? part.slice(0, -1) : part)
    buf.writeUInt32LE((hardened ? 0x80000000 : 0) + index, i * 4)
  })
  return buf
}

function statusWord(response: Buffer): number {
  return response.readUInt16BE(response.length - 2)
}

// The status word of an APDU, whether or not the transport treats it as an error.
async function send(transport: any, ins: number, p1: number, data: Buffer): Promise<number> {
  try {
    return statusWord(await transport.send(CLA, ins, p1, 0, data))
  } catch (e: any) {
    if (typeof e?.statusCode === 'number') return e.statusCode
    throw e
  }
}

// 1-of-1 mainnet P2SH with the device key alone, no on-device confirmation.
const MULTISIG_1_OF_1 = Buffer.from([0x00, 20, 0x01, 1, 1, 0])

async function contractCallWithString(app: StacksApp, value: string): Promise<Buffer> {
  const pk = await app.getAddressAndPubKey(PATH, AddressVersion.TestnetSingleSig)
  expect(pk.returnCode).toEqual(SW_OK)
  const tx = await makeUnsignedContractCall({
    contractAddress: 'ST000000000000000000002AMW42H',
    contractName: 'audit',
    functionName: 'call',
    functionArgs: [stringAsciiCV(value)],
    network: STACKS_TESTNET,
    fee: 10n,
    nonce: 0n,
    publicKey: pk.publicKey.toString('hex'),
  })
  return Buffer.from(tx.serialize(), 'hex')
}

describe('Audit 26-10-3001-REP', function () {
  // HIGH-5. The screen reads values as C strings, so `ok\0SPATTACKER` used to review as `ok` and
  // sign without the blind-signing screen. A string with any non-printable byte is now opaque, so
  // with blind signing off the device refuses it.
  test.each(models.filter(({ name }) => name === 'nanox'))('HIGH-5 refuses a NUL string without blind signing', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
      const blob = await contractCallWithString(app, 'ok\0SPATTACKER')

      const signatureRequest = app.sign(PATH, blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      // The single "cannot be clear-signed" screen; both buttons dismiss it.
      await sim.clickBoth(undefined, false)

      const signature = await signatureRequest
      expect(signature.returnCode).toEqual(SW_DATA_INVALID)
    } finally {
      await sim.close()
    }
  })

  // HIGH-5. With blind signing on, the review shows the type placeholder behind the warning,
  // never the text before the NUL.
  test.concurrent.each(models)('HIGH-5 shows a NUL string as opaque under blind signing', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.toggleBlindSigning()
      const app = new StacksApp(sim.getTransport())
      const blob = await contractCallWithString(app, 'ok\0SPATTACKER')

      const signatureRequest = app.sign(PATH, blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-audit_string_with_nul_blindsign`, true, 0, undefined, true)

      const signature = await signatureRequest
      expect(signature.returnCode).toEqual(SW_OK)
    } finally {
      await sim.close()
    }
  })

  // MEDIUM-2. The auditor's sequence: a multisig INIT with a valid path, a GET_AUTH_PUBKEY that
  // overwrites the first three components of the shared path (888'/0'/0'/0/0 here), then the
  // LAST chunk. The key returned must be the one for the path validated on INIT.
  test.concurrent.each(models)('MEDIUM-2 multisig derives from the INIT path despite an interleaved command', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const transport = sim.getTransport()
      const app = new StacksApp(transport)

      const expected = await app.getAddressAndPubKey(PATH, AddressVersion.MainnetSingleSig)
      expect(expected.returnCode).toEqual(SW_OK)

      let response = await transport.send(CLA, INS_GET_ADDR_MULTISIG, P1_INIT, 0, serializePath(PATH), [SW_OK])
      expect(statusWord(response)).toEqual(SW_OK)

      response = await transport.send(CLA, INS_GET_AUTH_PUBKEY, 0, 0, serializePath("m/888'/0'/0'"), [SW_OK])
      expect(statusWord(response)).toEqual(SW_OK)

      response = await transport.send(CLA, INS_GET_ADDR_MULTISIG, P1_LAST, 0, MULTISIG_1_OF_1, [SW_OK])
      expect(statusWord(response)).toEqual(SW_OK)
      const devicePublicKey = response.subarray(0, 33).toString('hex')

      expect(devicePublicKey).toEqual(expected.publicKey.toString('hex'))
    } finally {
      await sim.close()
    }
  })

  // MEDIUM-2. A transfer belongs to the INS that opened it: a LAST chunk from another chunked
  // instruction is refused, and the transfer is cancelled.
  test.concurrent.each(models)('MEDIUM-2 refuses chunks from another instruction', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const transport = sim.getTransport()

      const cases = [
        { init: INS_GET_ADDR_MULTISIG, last: INS_SIGN, path: PATH },
        { init: INS_SIGN, last: INS_SIGN_JWT, path: PATH },
        { init: INS_SIGN_JWT, last: INS_SIGN, path: "m/888'/0'/0'" },
      ]
      for (const { init, last, path } of cases) {
        expect(await send(transport, init, P1_INIT, serializePath(path))).toEqual(SW_OK)
        expect(await send(transport, last, P1_LAST, MULTISIG_1_OF_1)).toEqual(SW_TX_NOT_INITIALIZED)
        // Cancelled: the INS that opened it cannot finish it either.
        expect(await send(transport, init, P1_LAST, MULTISIG_1_OF_1)).toEqual(SW_TX_NOT_INITIALIZED)
      }
    } finally {
      await sim.close()
    }
  })
})
