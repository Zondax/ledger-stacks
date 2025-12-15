import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import StacksApp from '@zondax/ledger-stacks'

import stacksTx from '@stacks/transactions'
const {
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
  serializeCV,
  makeUnsignedContractDeploy,
  createStacksPublicKey,
  addressFromPublicKeys,
  AddressHashMode,
  AddressVersion,
  broadcastTransaction,
  PubKeyEncoding,
  createTransactionAuthField,
  StacksWireType,
  addressToString,
} = stacksTx

import stacksNetwork from '@stacks/network'
const { STACKS_TESTNET } = stacksNetwork

const PATH = "m/44'/5757'/0'/0/0"
const TESTNET_API = 'https://api.testnet.hiro.so'

// ============================================================================
// Test: Structured Message Signing
// ============================================================================

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

async function testStructuredMessage() {
    console.log('🔌 Connecting to Ledger device...')
    const transport = await TransportNodeHid.default.open();
    ledger_logs.listen((log) => {
        console.log(`${log.type} ${log.message}`)
    });

    const domain_serialized = serializeCV(DOMAIN).toString('hex')
    const msg_serialized = serializeCV(MSG).toString('hex')

    const app = new StacksApp.default(transport);
    const resp = await app.sign_structured_msg(PATH, domain_serialized, msg_serialized)

    console.log(resp)
    await transport.close()
}

// ============================================================================
// Test: Multisig 1/1 Contract Deploy on Testnet
// ============================================================================

// Generate a large contract (~80KB) to test with similar size to reported issue
function generateLargeContract(targetSizeKB = 80) {
  const targetSize = targetSizeKB * 1024

  let contract = `;; Large test contract for multisig deployment (~${targetSizeKB}KB)
;; This simulates a complex DeFi contract similar to dlmm-core

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u1001))
(define-constant ERR-INVALID-AMOUNT (err u1002))
(define-constant ERR-INSUFFICIENT-BALANCE (err u1003))
(define-constant ERR-POOL-NOT-FOUND (err u1004))
(define-constant ERR-INVALID-TOKEN (err u1005))

;; Data variables
(define-data-var contract-owner principal tx-sender)
(define-data-var total-value-locked uint u0)
(define-data-var protocol-fee-rate uint u30)
(define-data-var is-paused bool false)

;; Data maps
(define-map user-balances principal uint)
(define-map pool-reserves { pool-id: uint } { reserve-x: uint, reserve-y: uint })
(define-map user-positions { user: principal, pool-id: uint } { amount: uint, entry-price: uint })

;; Read-only functions
(define-read-only (get-owner)
  (ok (var-get contract-owner)))

(define-read-only (get-tvl)
  (ok (var-get total-value-locked)))

(define-read-only (get-user-balance (user principal))
  (ok (default-to u0 (map-get? user-balances user))))

`

  // Add many functions to reach target size
  let fnIndex = 0
  while (contract.length < targetSize) {
    // Add varied function types to simulate real contract
    const fnType = fnIndex % 4

    if (fnType === 0) {
      // Read-only getter function
      contract += `
(define-read-only (get-pool-data-${fnIndex.toString().padStart(4, '0')} (pool-id uint))
  (let (
    (reserves (default-to { reserve-x: u0, reserve-y: u0 } (map-get? pool-reserves { pool-id: pool-id })))
    (fee-rate (var-get protocol-fee-rate))
  )
  (ok {
    reserve-x: (get reserve-x reserves),
    reserve-y: (get reserve-y reserves),
    fee: fee-rate,
    pool-id: pool-id
  })))

`
    } else if (fnType === 1) {
      // Public function with validation
      contract += `
(define-public (update-position-${fnIndex.toString().padStart(4, '0')} (pool-id uint) (amount uint))
  (let (
    (sender tx-sender)
    (current-balance (default-to u0 (map-get? user-balances sender)))
    (pool-data (default-to { reserve-x: u0, reserve-y: u0 } (map-get? pool-reserves { pool-id: pool-id })))
  )
  (asserts! (not (var-get is-paused)) ERR-NOT-AUTHORIZED)
  (asserts! (> amount u0) ERR-INVALID-AMOUNT)
  (asserts! (>= current-balance amount) ERR-INSUFFICIENT-BALANCE)
  (map-set user-balances sender (- current-balance amount))
  (map-set pool-reserves { pool-id: pool-id }
    { reserve-x: (+ (get reserve-x pool-data) amount), reserve-y: (get reserve-y pool-data) })
  (ok true)))

`
    } else if (fnType === 2) {
      // Complex read-only with calculations
      contract += `
(define-read-only (calculate-swap-${fnIndex.toString().padStart(4, '0')} (pool-id uint) (amount-in uint) (is-x-to-y bool))
  (let (
    (pool-data (default-to { reserve-x: u0, reserve-y: u0 } (map-get? pool-reserves { pool-id: pool-id })))
    (reserve-in (if is-x-to-y (get reserve-x pool-data) (get reserve-y pool-data)))
    (reserve-out (if is-x-to-y (get reserve-y pool-data) (get reserve-x pool-data)))
    (fee-rate (var-get protocol-fee-rate))
    (amount-with-fee (/ (* amount-in (- u10000 fee-rate)) u10000))
    (numerator (* amount-with-fee reserve-out))
    (denominator (+ reserve-in amount-with-fee))
  )
  (ok {
    amount-out: (/ numerator denominator),
    fee-amount: (- amount-in amount-with-fee),
    price-impact: (/ (* amount-in u10000) reserve-in)
  })))

`
    } else {
      // Private helper function
      contract += `
(define-private (validate-and-update-${fnIndex.toString().padStart(4, '0')} (user principal) (pool-id uint) (delta int))
  (let (
    (current-position (default-to { amount: u0, entry-price: u0 }
      (map-get? user-positions { user: user, pool-id: pool-id })))
    (current-amount (get amount current-position))
    (new-amount (if (< delta 0)
      (if (>= current-amount (to-uint (* delta -1))) (- current-amount (to-uint (* delta -1))) u0)
      (+ current-amount (to-uint delta))))
  )
  (map-set user-positions { user: user, pool-id: pool-id }
    { amount: new-amount, entry-price: (get entry-price current-position) })
  (ok new-amount)))

`
    }
    fnIndex++
  }

  // Trim to exact size if needed
  if (contract.length > targetSize) {
    // Find last complete function
    const lastFnEnd = contract.lastIndexOf('\n)\n\n', targetSize)
    if (lastFnEnd > 0) {
      contract = contract.substring(0, lastFnEnd + 3)
    }
  }

  return contract
}

const CONTRACT_CODE = generateLargeContract(80)

async function getBalance(address) {
  const response = await fetch(`${TESTNET_API}/extended/v1/address/${address}/balances`)
  const data = await response.json()
  return BigInt(data.stx.balance)
}

async function getNonce(address) {
  const response = await fetch(`${TESTNET_API}/extended/v1/address/${address}/nonces`)
  const data = await response.json()
  return data.possible_next_nonce
}

async function requestFaucet(address) {
  console.log(`\n💰 Requesting STX from faucet for ${address}...`)
  const response = await fetch(`${TESTNET_API}/extended/v1/faucets/stx?address=${address}`, {
    method: 'POST'
  })
  const data = await response.json()
  if (data.success) {
    console.log(`✅ Faucet request successful! TxID: ${data.txId}`)
    console.log(`   Wait a few minutes for the transaction to confirm.`)
  } else {
    console.log(`❌ Faucet request failed:`, data)
  }
  return data
}

async function testMultisigContractDeploy() {
  console.log('🔌 Connecting to Ledger device...')
  const transport = await TransportNodeHid.default.open()

  ledger_logs.listen((log) => {
    if (log.type === 'apdu') {
      console.log(`   [APDU] ${log.message}`)
    }
  })

  const app = new StacksApp.default(transport)

  // Step 1: Get public key from Ledger
  console.log('\n📱 Getting public key from Ledger...')
  console.log(`   Path: ${PATH}`)

  const pkResponse = await app.getAddressAndPubKey(PATH, AddressVersion.TestnetSingleSig)
  if (pkResponse.returnCode !== 0x9000) {
    console.error('❌ Failed to get public key:', pkResponse.errorMessage)
    await transport.close()
    return
  }

  const devicePubKeyHex = pkResponse.publicKey.toString('hex')
  console.log(`✅ Public key: ${devicePubKeyHex}`)
  console.log(`   Single-sig address: ${pkResponse.address}`)

  // Step 2: Create multisig address
  console.log('\n🔐 Creating multisig 1/1 address...')
  const pubKey = createStacksPublicKey(devicePubKeyHex)

  const multisigAddressResult = addressFromPublicKeys(
    AddressVersion.TestnetMultiSig,
    AddressHashMode.P2SH,
    1,  // signatures required
    [pubKey]
  )

  // Handle different return formats
  let multisigAddressStr
  if (typeof multisigAddressResult === 'string') {
    multisigAddressStr = multisigAddressResult
  } else if (multisigAddressResult && multisigAddressResult.address) {
    multisigAddressStr = multisigAddressResult.address
  } else if (multisigAddressResult && multisigAddressResult.hash160) {
    // Convert to c32 address using addressToString
    multisigAddressStr = addressToString(multisigAddressResult)
  }

  const multisigAddress = { address: multisigAddressStr }
  console.log(`✅ Multisig address: ${multisigAddress.address}`)

  // Step 3: Check balance
  console.log('\n💵 Checking balance...')
  let balance = await getBalance(multisigAddress.address)
  console.log(`   Balance: ${balance} uSTX (${Number(balance) / 1_000_000} STX)`)

  if (balance < 10000n) {
    console.log('\n⚠️  Insufficient balance for transaction.')
    console.log('   Options:')
    console.log('   1. Request from faucet (will take a few minutes)')
    console.log('   2. Send STX manually to the multisig address')

    // Auto-request from faucet
    await requestFaucet(multisigAddress.address)
    console.log('\n⏳ Waiting 30 seconds for faucet transaction...')
    await new Promise(resolve => setTimeout(resolve, 30000))

    balance = await getBalance(multisigAddress.address)
    console.log(`   New balance: ${balance} uSTX`)

    if (balance < 10000n) {
      console.log('\n❌ Still insufficient balance. Please wait for faucet or send STX manually.')
      console.log(`   Multisig address: ${multisigAddress.address}`)
      await transport.close()
      return
    }
  }

  // Step 4: Get nonce
  const nonce = await getNonce(multisigAddress.address)
  console.log(`   Nonce: ${nonce}`)

  // Step 5: Create unsigned contract deploy transaction
  console.log('\n📝 Creating unsigned contract deploy transaction...')
  console.log(`   Contract code size: ${(CONTRACT_CODE.length / 1024).toFixed(2)} KB (${CONTRACT_CODE.length} bytes)`)
  const contractName = `large-contract-${Date.now()}`

  const txOptions = {
    contractName: contractName,
    codeBody: CONTRACT_CODE,
    network: STACKS_TESTNET,
    fee: 100000n,  // Large contracts need higher fees (~1 STX per KB)
    nonce: nonce,
    numSignatures: 1,
    publicKeys: [devicePubKeyHex],
    clarityVersion: 4,
  }

  const unsignedTx = await makeUnsignedContractDeploy(txOptions)
  const serializedTx = unsignedTx.serialize()
  console.log(`✅ Transaction created`)
  console.log(`   Contract name: ${contractName}`)
  console.log(`   Serialized length: ${serializedTx.length} bytes`)

  // Step 6: Sign with Ledger
  console.log('\n✍️  Signing transaction with Ledger...')
  console.log('   Please review and approve on your device.')

  const signResponse = await app.sign(PATH, Buffer.from(serializedTx, 'hex'))

  if (signResponse.returnCode !== 0x9000) {
    console.error('❌ Signing failed:', signResponse.errorMessage)
    await transport.close()
    return
  }

  console.log('✅ Transaction signed!')
  console.log(`   Post-sign hash: ${signResponse.postSignHash.toString('hex')}`)
  console.log(`   Signature VRS: ${signResponse.signatureVRS.toString('hex')}`)

  // Step 7: Apply signature to transaction
  console.log('\n🔧 Applying signature to transaction...')

  // For multisig, we need to add the signature as an auth field
  // Use signatureVRS which is in the correct format: v[1] + r[32] + s[32]
  const signatureVRS = signResponse.signatureVRS.toString('hex')

  // Create the auth field with the signature using the proper helper
  const authField = createTransactionAuthField(PubKeyEncoding.Compressed, {
    type: StacksWireType.MessageSignature,
    data: signatureVRS,
  })

  // Add the signature to the transaction's auth fields
  unsignedTx.auth.spendingCondition.fields = [authField]

  const signedTx = unsignedTx

  // Step 8: Broadcast transaction
  console.log('\n📡 Broadcasting transaction to testnet...')

  try {
    const broadcastResponse = await broadcastTransaction({
      transaction: signedTx,
      network: STACKS_TESTNET,
    })

    // Handle different response formats
    const txid = typeof broadcastResponse === 'string'
      ? broadcastResponse
      : broadcastResponse.txid

    if (txid && !broadcastResponse.error) {
      console.log('✅ Transaction broadcast successful!')
      console.log(`   TxID: ${txid}`)
      console.log(`   Explorer: https://explorer.hiro.so/txid/${txid}?chain=testnet`)
    } else {
      console.log('❌ Broadcast failed:', broadcastResponse)
    }
  } catch (error) {
    console.error('❌ Broadcast error:', error.message)

    // Try alternative: broadcast raw transaction
    console.log('\n🔄 Trying alternative broadcast method...')
    const rawTx = signedTx.serialize().toString('hex')
    console.log(`   Raw TX (first 100 chars): ${rawTx.substring(0, 100)}...`)

    const response = await fetch(`${TESTNET_API}/v2/transactions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: Buffer.from(rawTx, 'hex')
    })

    if (response.ok) {
      const txId = await response.text()
      console.log('✅ Transaction broadcast successful!')
      console.log(`   TxID: ${txId}`)
      console.log(`   Explorer: https://explorer.hiro.so/txid/${txId}?chain=testnet`)
    } else {
      const errorText = await response.text()
      console.log('❌ Alternative broadcast failed:', errorText)
    }
  }

  await transport.close()
  console.log('\n✅ Done!')
}

// ============================================================================
// Main - Comment/uncomment to run desired test
// ============================================================================

;(async () => {
  try {
    // Test structured message signing
    // await testStructuredMessage()

    // Test multisig 1/1 contract deploy on testnet
    await testMultisigContractDeploy()

  } catch (error) {
    console.error('❌ Error:', error)
    process.exit(1)
  }
})()
