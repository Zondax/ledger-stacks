/**
 * The argument walk at its limits, on the emulated device.
 *
 * Flattening runs a recursive walk on the device stack -- once at parse to count leaves, again
 * for every screen to locate one -- and renders each leaf through a 256-byte stack buffer. The
 * host tests prove the walk gives the right answer; only the device can prove it has the stack
 * to give it. Zemu runs the real firmware with the real stack canary, so if either walk overran,
 * the app would halt and the signature would never arrive.
 *
 * No snapshots: a 200-leaf review is hundreds of screens per model, and the screens themselves
 * are pinned elsewhere. The assertion is that the transaction reviews and signs.
 */
import Zemu, { DEFAULT_START_OPTIONS, isTouchDevice } from '@zondax/zemu'
import StacksApp from '@zondax/ledger-stacks'
import { AddressVersion, ClarityValue, listCV, makeUnsignedContractCall, tupleCV, uintCV } from '@stacks/transactions'
import { STACKS_TESTNET } from '@stacks/network'
import { APP_SEED, models } from './common'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

// A Nano pages ~200 leaves over ~400 screens, one click each.
jest.setTimeout(900000)
const NAVIGATION_TIMEOUT = 800000

/** Mirrors MAX_ARG_DISPLAY_ITEMS in app/rust/src/parser/transaction_payload/contract_call.rs. */
const MAX_ARG_DISPLAY_ITEMS = 200
/** The deepest nesting `walk_value` flattens: a leaf at depth TX_DEPTH_LIMIT - 1. */
const MAX_FLATTEN_DEPTH = 7

interface Limit {
  name: string
  args: ClarityValue[]
}

const LIMITS: Limit[] = [
  {
    // Exactly the leaf budget, in one container: the widest walk the device will flatten.
    name: 'list_at_leaf_budget',
    args: [listCV(Array.from({ length: MAX_ARG_DISPLAY_ITEMS }, (_, i) => uintCV(i)))],
  },
  {
    // The deepest nesting the walk flattens, alternating tuple and list so both descent paths
    // and the key-path builder are exercised: arg0.a[0].a[0].a[0].a
    name: 'nesting_at_depth_limit',
    args: [
      Array.from({ length: MAX_FLATTEN_DEPTH }, (_, i) => i).reduce<ClarityValue>(
        (inner, depth) => (depth % 2 === 0 ? tupleCV({ a: inner }) : listCV([inner])),
        uintCV(1),
      ),
    ],
  },
]

describe('ArgumentLimits', function () {
  const cases = models.flatMap((m) => LIMITS.map((limit) => ({ m, limit })))

  test.concurrent.each(cases)('signs $limit.name on $m.name', async function ({ m, limit }) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      expect(pkResponse.returnCode).toEqual(0x9000)

      const transaction = await makeUnsignedContractCall({
        contractAddress: 'ST000000000000000000002AMW42H',
        contractName: 'limits',
        functionName: 'call',
        functionArgs: limit.args,
        network: STACKS_TESTNET,
        fee: 10n,
        nonce: 0n,
        publicKey: pkResponse.publicKey.toString('hex'),
      })
      const blob = Buffer.from(transaction.serialize(), 'hex')

      // No blind-signing opt-in: both shapes are inside the budget and must review normally.
      const signatureRequest = app.sign(path, blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      const approve = isTouchDevice(m.name) ? 'Hold to sign' : 'APPROVE'
      await sim.navigateUntilText('.', `${m.prefix.toLowerCase()}-${limit.name}`, approve, true, false, 0, NAVIGATION_TIMEOUT)

      const signature = await signatureRequest
      expect(signature.returnCode).toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })
})
