/**
 * The review fast path, on the emulated device.
 *
 * A long blind-signed review offers a way to the approval without reading every item. On a Nano
 * that is one screen at a fixed place in the review -- "Press right to read / Double-press to
 * skip" -- and both buttons take it; on the touch devices it is NBGL's "Skip" control.
 *
 * Only blind-signed reviews offer it. On an ordinary review the shortcut would be a way to
 * approve without reading, which is blind signing without the warning or the opt-in.
 *
 * Skipping lands on "ACCEPT RISK AND APPROVE", not the plain approval: a user who opted in still
 * acknowledges the risk, they just do not page through items the device has already said it
 * cannot fully explain. That is also the case that used to hang -- the skip asked to start at a
 * step the blind-signing flow does not contain, so nothing happened.
 *
 * Nano only. The touch devices take the same path through NBGL's own control, whose position is
 * not addressable from the test harness; their snapshots record that the control appears.
 */
import Zemu, { ButtonKind, DEFAULT_START_OPTIONS, INavElement } from '@zondax/zemu'
import { getTouchElement } from '@zondax/zemu/dist/buttons'
import { ActionKind, IButton, SwipeDirection } from '@zondax/zemu/dist/types'
import StacksApp from '@zondax/ledger-stacks'
import { AddressVersion } from '@stacks/transactions'
import { createHash } from 'crypto'
import * as fs from 'fs'
import * as path from 'path'
import { APP_SEED, models } from './common'

const RIPEMD160 = require('ripemd160')

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(300000)

/** The skip screen is a bagl construct; the touch devices use NBGL's own Skip control. */
const buttonModels = models.filter(m => m.name === 'nanox' || m.name === 'nanosp')
const touchModels = models.filter(m => m.name === 'stax' || m.name === 'flex' || m.name === 'apex_p')

/**
 * Where NBGL draws its Skip control, per model. Zemu has no `ButtonKind` for it, so this is the
 * one position the test has to carry itself; every other target comes from `getTouchElement`.
 * Read off the review snapshots -- it sits right-aligned in the header. An SDK bump that moves
 * the header breaks these tests, which is most of why they are worth having.
 */
const SKIP_CONTROL: Record<string, IButton> = {
  flex: { x: 420, y: 47, delay: 0.5, direction: SwipeDirection.NoSwipe },
  stax: { x: 348, y: 44, delay: 0.5, direction: SwipeDirection.NoSwipe },
  apex_p: { x: 268, y: 31, delay: 0.5, direction: SwipeDirection.NoSwipe },
}

const touch = (button: IButton): INavElement => ({ type: ActionKind.Touch, button })

/** Taps needed before the Skip control is drawn: past the review's own title page. */
const TAPS_BEFORE_SKIP = 2

/** Both buttons at once. `button` is unused on a two-button device but the type requires it. */
const bothClick: INavElement = {
  type: ActionKind.BothClick,
  button: { x: 0, y: 0, delay: 0, direction: SwipeDirection.NoSwipe },
}

/**
 * Blind-signing warning, "could lose all assets", review start -- and then the offer, which sits
 * at a fixed slot in the review flow before the first item. It is offered once, up front; reading
 * the transaction afterwards is uninterrupted.
 */
const CLICKS_TO_SKIP_OFFER = 3

/**
 * A captured HODLMM "remove liquidity" position: 84 post-conditions over 61 bins, and a list
 * argument far past the leaf budget, so the transaction is gated *and* long -- 27 display items.
 * The shape this fast path exists for.
 */
function dlmmBlob(publicKeyHex: string): Buffer {
  const fixtures: Record<string, string> = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'dlmm_post_conditions.json'), 'utf8'))
  const blob = Buffer.from(fixtures['raw-tx-2'], 'hex')
  // The blob's origin is the reporter's key, which would fail the device signer check. Patch the
  // 20-byte signer hash at offset 7 to this device's, isolating the UI from auth.
  const sha = createHash('sha256').update(Buffer.from(publicKeyHex, 'hex')).digest()
  new RIPEMD160().update(sha).digest().copy(blob, 7)
  return blob
}

describe('ReviewFastPath', function () {
  test.concurrent.each(buttonModels)('skips a blind-signed review on $name', async function (m) {
    const sim = new Zemu(m.path)
    const dpath = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const pkResponse = await app.getAddressAndPubKey(dpath, AddressVersion.MainnetSingleSig)
      expect(pkResponse.returnCode).toEqual(0x9000)

      await sim.toggleBlindSigning()

      const signatureRequest = app.sign(dpath, dlmmBlob(pkResponse.publicKey.toString('hex')))
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      // Read as far as the first offer to skip, take it, then sign from where it lands -- which
      // must be the risk acknowledgement, not the plain approval.
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-review_fast_path_blindsign`, [
        CLICKS_TO_SKIP_OFFER,
        bothClick,
        bothClick,
      ])

      const signature = await signatureRequest
      expect(signature.returnCode).toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(touchModels)('skips a blind-signed review on $name', async function (m) {
    const sim = new Zemu(m.path)
    const dpath = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())

      const pkResponse = await app.getAddressAndPubKey(dpath, AddressVersion.MainnetSingleSig)
      expect(pkResponse.returnCode).toEqual(0x9000)

      await sim.toggleBlindSigning()

      const signatureRequest = app.sign(dpath, dlmmBlob(pkResponse.publicKey.toString('hex')))
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      // Into the review far enough for the Skip control to be drawn, take it, confirm the SDK's
      // "Skip review?" prompt, then sign from where it lands -- the risk acknowledgement.
      const schedule: INavElement[] = []
      for (let i = 0; i < TAPS_BEFORE_SKIP; i++) {
        schedule.push(touch(getTouchElement(m.name, ButtonKind.NavRightButton)))
      }
      schedule.push(touch(SKIP_CONTROL[m.name]))
      schedule.push(touch(getTouchElement(m.name, ButtonKind.ConfirmYesButton)))
      schedule.push(touch(getTouchElement(m.name, ButtonKind.ApproveHoldButton)))

      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-review_fast_path_blindsign`, schedule)

      const signature = await signatureRequest
      expect(signature.returnCode).toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })
})
