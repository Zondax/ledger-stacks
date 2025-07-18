import { FungibleConditionCode } from '@stacks/transactions'
import { IDeviceModel } from '@zondax/zemu'
import BN from 'bn.js'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')
const APP_PATH_ST = Resolve('../app/output/app_stax.elf')
const APP_PATH_FL = Resolve('../app/output/app_flex.elf')

export const models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
  { name: 'flex', prefix: 'FL', path: APP_PATH_FL },
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
          amount: new BN(1000000)
        },
        {
          address: 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5',
          code: FungibleConditionCode.LessEqual,
          amount: new BN(2500)
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
          amount: new BN(1000000)
        },
        {
          address: 'ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5',
          code: FungibleConditionCode.Equal,
          amount: new BN(1005020)
        }
      ],
      snapshotSuffix: 'sign_sip10_contract_with_post_conditions_hidden'
    }
  ]
