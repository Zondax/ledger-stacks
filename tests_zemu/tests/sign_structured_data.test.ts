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

import {
  AddressVersion,
  standardPrincipalCV,
  uintCV,
  intCV,
  stringAsciiCV,
  stringUtf8CV,
  tupleCV,
  bufferCV,
  noneCV,
  someCV,
  responseOkCV,
  responseErrorCV,
  trueCV,
  falseCV,
  contractPrincipalCV,
  listCV,
  serializeCV,
} from '@stacks/transactions'

import { ec as EC } from 'elliptic'

const sha256 = require('js-sha256').sha256

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

const DOMAIN = tupleCV({
  name: stringAsciiCV('Stacks'),
  version: stringAsciiCV('1.0.0'),
  'chain-id': uintCV(153987),
})

const MSG_TUPLE = tupleCV({
  name: DOMAIN,
  version: listCV([DOMAIN, DOMAIN, uintCV(586987)]),
  'chain-id': uintCV(1),
  a: intCV(-1),
  b: bufferCV(Buffer.from('abcdefgh')),
  m: listCV([intCV(-1), intCV(-1), intCV(-1), intCV(-1)]),
  result_call: responseOkCV(stringAsciiCV('done')),
  error_msg: responseErrorCV(stringUtf8CV('unknown URI')),
  nested: someCV(listCV([noneCV(), someCV(intCV(-100))])),
  principal: standardPrincipalCV('SP2JXKMSH007NPYAQHKJPQMAQYAD90NQGTVJVQ02B'),
})

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

const MSG_STRING = stringAsciiCV(
  'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas risus odio, sagittis non turpis vel, imperdiet pharetra quam. Cras fermentum nisi leo. Aliquam bibendum lacus pulvinar, ultrices urna in, faucibus quam. Maecenas eu commodo mi. Vivamus lorem ante, efficitur eget condimentum quis, malesuada viverra sem. Donec egestas egestas erat, vitae facilisis tellus bibendum varius. Maecenas ac porta libero, ac finibus risus. Quisque dictum lacinia tortor, sed convallis mi condimentum eget. In interdum mauris nisi, nec elementum nibh bibendum sit amet. Mauris auctor vulputate enim, sit amet egestas eros. Integer rhoncus ipsum purus, sed pulvinar erat suscipit interdum. In dolor dui, aliquam vitae iaculis vitae, facilisis in orci. Cras volutpat ultrices mauris. Mauris malesuada, nulla sit amet volutpat iaculis, felis tortor pharetra mauris, sed ullamcorper ante lectus vel quam.',
)

const MSG_EMPTY_LIST = listCV([])

const SIGN_TEST_DATA = [
  {
    name: 'tuple',
    op: MSG_TUPLE,
  },
  {
    name: 'string',
    op: MSG_STRING,
  },
  {
    name: 'empty_list',
    op: MSG_EMPTY_LIST,
  },
  {
    name: 'simple_number',
    op: intCV(-125689),
  },
  {
    name: 'some_tuple',
    op: someCV(MSG_TUPLE),
  },
  {
    name: 'big_list_tuple',
    op: listCV([MSG_TUPLE, MSG_TUPLE, MSG_TUPLE]), // requires a recursion limit of 20
  },
  {
    name: 'big_tuple',
    op: BIG_TUPLE,
  },
]

jest.setTimeout(180000)

describe.each(models)('StructuredData', function (m) {
  test.concurrent.each(SIGN_TEST_DATA)(`sign_structured_data_tuple`, async function ({ name, op }) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/0'/0/0"

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const domain_serialized = serializeCV(DOMAIN).toString('hex')
      const msg_serialized = serializeCV(op).toString('hex')

      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.MainnetSingleSig)

      const signatureRequest = app.sign_structured_msg(path, domain_serialized, msg_serialized)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-structured_data_${name}`)

      // Check the signature
      const signature = await signatureRequest

      console.log(signature)
      expect(signature.returnCode).toEqual(0x9000)
      expect(signature.errorMessage).toEqual('No errors')

      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const testPublicKey = pkResponse.publicKey.toString('hex')
      console.log('publicKey ', testPublicKey)

      const domain_hash = sha256(Buffer.from(domain_serialized, 'hex'))
      const msg_hash = sha256(Buffer.from(msg_serialized, 'hex'))
      const hash = sha256(Buffer.concat([Buffer.from('SIP018', 'ascii'), Buffer.from(domain_hash, 'hex'), Buffer.from(msg_hash, 'hex')]))

      //Verify signature
      // Verify we sign the same hash
      const postSignHash = signature.postSignHash.toString('hex')
      console.log('postSignHash: ', postSignHash)

      expect(hash).toEqual(postSignHash)

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
})
