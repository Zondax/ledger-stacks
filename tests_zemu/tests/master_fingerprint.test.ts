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
import { APP_SEED, models } from './common'

const RIPEMD160 = require('ripemd160')
const sha256 = require('js-sha256').sha256

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(180000)

describe('MasterFingerprint', function () {
  test.concurrent.each(models)(`get master key fingerprint`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const masterKey = "020e06f6fc9a16fe7fad1d11566ad7a68d571bdde3a141a4dc9907d0cc13f59362"
      const masterKeyBuffer = Buffer.from(masterKey, 'hex')
      const sha256Hash = Buffer.from(sha256(masterKeyBuffer), 'hex')
      const ripemd = new RIPEMD160()
      const masterKeyFingerprint = ripemd.update(sha256Hash).digest().slice(0, 4)

      const response = await app.getMasterFingerprint()
      console.log(response)
      expect(response.returnCode).toEqual(0x9000)
      expect(response.errorMessage).toEqual('No errors')

      // Master key fingerprint should be 4 bytes (8 hex characters)
      expect(response.fingerprint).toHaveLength(4)
      expect(response.fingerprint).toBeInstanceOf(Buffer)

      // Verify fingerprint is consistent across calls
      const response2 = await app.getMasterFingerprint()
      expect(response2.returnCode).toEqual(0x9000)
      expect(response.fingerprint.toString('hex')).toEqual(response2.fingerprint.toString('hex'))

      expect(response.fingerprint.toString('hex')).toEqual(masterKeyFingerprint.toString('hex'))
    } finally {
      await sim.close()
    }
  })
})
