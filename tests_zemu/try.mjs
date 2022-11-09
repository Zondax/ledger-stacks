import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import StacksApp from '@zondax/ledger-stacks'

import {
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
  listCV,
  serializeCV
} from '@stacks/transactions'

const PATH = "m/44'/5757'/0'/0/0"

const DOMAIN = tupleCV({
    'name': stringAsciiCV("Stacks"),
    'version': stringAsciiCV("2.5.3"),
    'chain-id': uintCV(1)
})

const MSG_TUPLE = tupleCV({
    'name': DOMAIN,
    'version': listCV([DOMAIN, DOMAIN, uintCV(586987)]),
    'chain-id': uintCV(1),
    'a': intCV(-1),
    'b': bufferCV(Buffer.from('abcdefgh')),
    'm': listCV([intCV(-1),intCV(-1),intCV(-1),intCV(-1)]),
    'result_call': responseOkCV(stringAsciiCV("done")),
    'error_msg': responseErrorCV(stringUtf8CV("unknown URI")),
    'nested': someCV(listCV([noneCV(), someCV(intCV(-100))])),
    'principal': standardPrincipalCV('SP2JXKMSH007NPYAQHKJPQMAQYAD90NQGTVJVQ02B'),
})

const MSG = listCV([MSG_TUPLE, MSG_TUPLE, MSG_TUPLE])

async function main() {
    const transport = await TransportNodeHid.default.open();
    ledger_logs.listen((log) => {
        console.log(`${log.type} ${log.message}`)
    });

    const domain_serialized = serializeCV(DOMAIN).toString('hex')
    const msg_serialized = serializeCV(MSG).toString('hex')

    const app = new StacksApp.default(transport);
    const resp = await app.sign_structured_msg(PATH, domain_serialized, msg_serialized)

    console.log(resp)
}

; (async () => {
  await main()
})()
