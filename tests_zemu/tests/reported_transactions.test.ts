/**
 * Transactions reported from the field as blind-signing false positives.
 *
 * Each one is an ordinary swap that the device had everything it needed to render, but which was
 * pushed behind the "you could lose all your assets" opt-in because one argument happened to be a
 * tuple, an optional, or an empty list. They are kept here as the regression the rendering work
 * exists to prevent: if any of them starts demanding blind signing again, these fail.
 *
 * The contract, function, arguments and post-conditions are taken verbatim from the wallet
 * requests in the reports. Only the origin differs -- it has to be the emulator's own key, or the
 * device rejects the transaction as not being for this signer.
 */
import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
import StacksApp from '@zondax/ledger-stacks'
import { AddressVersion, deserializeCV, makeUnsignedContractCall } from '@stacks/transactions'
import { STACKS_MAINNET, STACKS_TESTNET } from '@stacks/network'
import { APP_SEED, models } from './common'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(180000)

interface ReportedTx {
  /** Snapshot name, and what the report was about. */
  name: string
  /** What used to fire the gate. */
  gatedOn: string
  contract: string
  functionName: string
  /** Serialized Clarity values, exactly as the wallet sent them. */
  functionArgs: string[]
  /** Serialized post-conditions, exactly as the wallet sent them. */
  postConditions?: string[]
  mainnet: boolean
}

const REPORTED: ReportedTx[] = [
  {
    // app.bitflow.finance swap-helper-a: arg3 and arg4 are tuples of contract principals. Three
    // addresses in total, every one of them displayable -- the device just had no way to show a
    // tuple, so it printed "is Tuple" and demanded blind signing.
    name: 'bitflow_swap_tuple_args',
    gatedOn: 'tuple arguments',
    contract: 'SM1793C4R5PZ4NS4VQ4WMP7SKKYVH8JZEWSZ9HCCR.xyk-swap-helper-v-1-3',
    functionName: 'swap-helper-a',
    functionArgs: [
      '0100000000000000000000000000002710',
      '0100000000000000000000000000000002',
      '09',
      '0c00000002016106144e91b0982dbe4ae49bb9394b1f339fb7144beee60f746f6b656e2d7374782d762d312d3201620614f6decc7cfff2a413bd7cd4f53c25ad7fd1899acc0a736274632d746f6b656e',
      '0c00000001016106144e91b0982dbe4ae49bb9394b1f339fb7144beee61778796b2d706f6f6c2d736274632d7374782d762d312d31',
    ],
    postConditions: [
      '000216f4b1aa40ed3e9c9990f099736006887e66cae1cc010000000000002710',
      '0103144e91b0982dbe4ae49bb9394b1f339fb7144beee61778796b2d706f6f6c2d736274632d7374782d762d312d3114f6decc7cfff2a413bd7cd4f53c25ad7fd1899acc0a736274632d746f6b656e0a736274632d746f6b656e030000000000000002',
    ],
    mainnet: true,
  },
  {
    // app.alexlab.co swap-helper: arg4 is `(some u493568)`. A single number behind a wrapper the
    // device never unwrapped, so it showed "Option: Some" and gated the swap.
    name: 'alex_swap_optional_arg',
    gatedOn: 'an optional argument',
    contract: 'SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM.amm-pool-v2-01',
    functionName: 'swap-helper',
    functionArgs: [
      '0616bad390278c2d8d61d49bce446eaebd9b8c0314550a746f6b656e2d61627463',
      '0616bad390278c2d8d61d49bce446eaebd9b8c0314550b746f6b656e2d7375736474',
      '0100000000000000000000000005f5e100',
      '010000000000000000000000000000000a',
      '0a0100000000000000000000000000078800',
    ],
    postConditions: [
      '010216f4b1aa40ed3e9c9990f099736006887e66cae1cc16bad390278c2d8d61d49bce446eaebd9b8c0314550a746f6b656e2d616274630b627269646765642d62746305000000000000000a',
      '010316402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0f616d6d2d7661756c742d76322d303116bad390278c2d8d61d49bce446eaebd9b8c0314550b746f6b656e2d73757364740c627269646765642d75736474030000000000078800',
    ],
    mainnet: true,
  },
  {
    // The testnet report: the first argument was an empty list, `0b00000000`. Nothing whatsoever
    // was hidden, and the gate fired on the type name alone. Rebuilt here from that shape -- the
    // reported transaction is a testnet blob we do not carry.
    name: 'empty_list_arg',
    gatedOn: 'an empty list argument',
    contract: 'SP000000000000000000002Q6VF78.pox',
    functionName: 'stack-stx',
    functionArgs: ['0b00000000'],
    mainnet: false,
  },
]

describe('ReportedTransactions', function () {
  const cases = models.flatMap((m) => REPORTED.map((tx) => ({ m, tx })))

  test.concurrent.each(cases)('reviews $tx.name without blind signing', async function ({ m, tx }) {
    const sim = new Zemu(m.path)
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const version = tx.mainnet ? AddressVersion.MainnetSingleSig : AddressVersion.TestnetSingleSig
      const pkResponse = await app.getAddressAndPubKey(path, version)
      expect(pkResponse.returnCode).toEqual(0x9000)

      const [contractAddress, contractName] = tx.contract.split('.')
      const transaction = await makeUnsignedContractCall({
        contractAddress,
        contractName,
        functionName: tx.functionName,
        functionArgs: tx.functionArgs.map((arg) => deserializeCV(arg)),
        postConditionMode: 'deny',
        postConditions: tx.postConditions,
        network: tx.mainnet ? STACKS_MAINNET : STACKS_TESTNET,
        fee: 10n,
        nonce: 0n,
        publicKey: pkResponse.publicKey.toString('hex'),
      })

      const blob = Buffer.from(transaction.serialize(), 'hex')

      // No sim.toggleBlindSigning(): the point of the test is that this reviews like any other
      // transaction. If the gate comes back, the app answers parser_blindsign_mode_required and
      // the review screens never appear.
      const signatureRequest = app.sign(path, blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${tx.name}`)

      const signature = await signatureRequest
      expect(signature.returnCode).toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })
})
