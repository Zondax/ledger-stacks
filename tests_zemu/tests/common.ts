import { FungibleConditionCode } from '@stacks/transactions'
import { IDeviceModel } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')
const APP_PATH_ST = Resolve('../app/output/app_stax.elf')
const APP_PATH_FL = Resolve('../app/output/app_flex.elf')
const APP_PATH_APEX = Resolve('../app/output/app_apex_p.elf')

export const models: IDeviceModel[] = [
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
  { name: 'flex', prefix: 'FL', path: APP_PATH_FL },
  { name: 'apex_p', prefix: 'AP', path: APP_PATH_APEX },
]

export interface SignatureTestCase {
  name: string
  blob: Buffer
  expectedSignatureVRS: string
}

export const SIGNATURE_TEST_CASES: SignatureTestCase[] = [
  {
    name: 'non-sponsored-hex',
    blob: Buffer.from(
      '0000000001040060dbb32efe0c56e1d418c020f4cb71c556b6a60d00000000000000dc000000000000cc230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000302000000000216debc095099629badb11b9d5335e874d12f1f1d450973656e642d6d616e790973656e642d6d616e7900000000',
      'hex'
    ),
    expectedSignatureVRS: '01c8d7da3f3a73a80494c97f25633703cfd07c04a40c440cfdd5a606fabed9476a2ee834274e75e0f0b1af4c66c0364863835b75f46d6f7b4b1adca79abf2ed698',
  },
  {
    name: 'sponsored-hex',
    blob: Buffer.from(
      '0000000001050060dbb32efe0c56e1d418c020f4cb71c556b6a60d00000000000000dc000000000000cc230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000029cfc6376255a78451eeb4b129ed8eacffa2feef000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000302000000000216debc095099629badb11b9d5335e874d12f1f1d450973656e642d6d616e790973656e642d6d616e7900000000',
      'hex'
    ),
    expectedSignatureVRS: '000a9dd6629952698a409798862d1facc6e2160f3b62f254278f95c8254569951253ff43a182fb6f002ccef22ef410125eb9c4b7f3a4f765bebcf128815d876173',
  },
]

export const SIP10_DATA = [
    {
      name: 'sign_sip10_contract',
      postConditions: undefined,
      snapshotSuffix: 'sign_sip10_contract'
    },
    {
      name: 'sign_sip10_contract_with_post_conditions',
      postConditions: [
        {
          address: 'SP2ZD731ANQZT6J4K3F5N8A40ZXWXC1XFXHVVQFKE',
          code: FungibleConditionCode.GreaterEqual,
          amount: 1000000n
        },
        {
          address: 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5',
          code: FungibleConditionCode.LessEqual,
          amount: 2500n
        }
      ],
      snapshotSuffix: 'sign_sip10_contract_with_post_conditions'
    },
    {
      name: 'sign_sip10_contract_with_post_conditions_hidden',
      postConditions: [
        {
          address: 'SP2ZD731ANQZT6J4K3F5N8A40ZXWXC1XFXHVVQFKE',
          code: FungibleConditionCode.Equal,
          amount: 1000000n
        },
        {
          address: 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5',
          code: FungibleConditionCode.Equal,
          amount: 1005020n
        }
      ],
      snapshotSuffix: 'sign_sip10_contract_with_post_conditions_hidden'
    }
  ]
