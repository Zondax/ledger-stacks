# Stacks App

## General structure

The general structure of commands and responses is as follows:

#### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0x09 |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code | Description              | Returned when                                                                                                                                                   |
| ----------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x9000      | Success                  | The command completed. Chunked commands also answer 0x9000, with no data, to every INIT and ADD chunk.                                                        |
| 0x6700      | Wrong length             | The APDU is shorter than 5 bytes, the derivation path is shorter than the command expects, or the multisig payload length does not match its header.          |
| 0x6982      | Empty buffer             | The APDU carries no data at all (reported by the zxlib main loop before dispatch).                                                                                |
| 0x6983      | Output buffer too small  | A chunk would overflow the buffer that holds the reassembled payload. The transfer is cancelled and must start again from INIT.                                 |
| 0x6984      | Data invalid             | The derivation path is not allowed for this command, a field is out of range, the payload does not parse (the response then carries the error message as ASCII), the address could not be built, or the user dismissed the blind-signing screen. |
| 0x6986      | Command not allowed      | A review is already on screen, the device PIN is not validated, or the user rejected the request.                                                              |
| 0x6987      | Transfer not initialised | An ADD or LAST chunk arrived with no INIT before it, or the transfer was opened by a different INS. In the second case the transfer is cancelled.              |
| 0x6B00      | Invalid P1/P2            | P2 is not 0 on a chunked command, or P1 is not a known chunk type (INIT, ADD, LAST).                                                                           |
| 0x6D00      | INS not supported        | The INS is unknown.                                                                                                                                             |
| 0x6E00      | CLA not supported        | The CLA is not 0x09.                                                                                                                                            |
| 0x6F01      | Sign/verify error        | Signing failed after the user approved: the signing hash could not be computed, the signature could not be produced, or the payload type is unknown.           |
| 0x68xx      | Internal error           | An exception the SDK raised with a code outside 0x6xxx, reported as 0x6800 with its low 11 bits.                                                                |
| 0x6400      | Execution error          | Never set by the application; only seen if the SDK raises it.                                                                                                   |
| 0x6F00      | Unknown                  | Never set by the application; only seen if the SDK raises it.                                                                                                   |

#### Chunked commands

INS_SIGN_SECP256K1 (0x02), INS_SIGN_JWT_SECP256K1 (0x04) and INS_GET_ADDR_MULTISIG (0x07) send their payload in chunks of up to
250 bytes: P1 = 0x00 (INIT) carries the derivation path, then any number of P1 = 0x01 (ADD) chunks and one P1 = 0x02 (LAST) chunk carry
the payload, and P2 is 0 on every chunk.

A transfer belongs to the INS that sent its INIT chunk. ADD and LAST chunks with another INS are refused with 0x6987 and cancel the
transfer. The device derives from the path validated on the INIT chunk, even if other commands run between INIT and LAST.

---

## Command definition

### GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x09     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| TEST    | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (1) | Version Major    |                                 |
| MINOR   | byte (1) | Version Minor    |                                 |
| PATCH   | byte (1) | Version Patch    |                                 |
| LOCKED  | byte (1) | Device is locked |                                 |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

### INS_GET_ADDR_SECP256K1

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x09       |
| INS     | byte (1) | Instruction ID            | 0x01       |
| P1      | byte (1) | Request User confirmation | No = 0     |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| Path[0] | byte (4) | Derivation Path Data      | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data      | 0x8000167d |
| Path[2] | byte (4) | Derivation Path Data      | ?          |
| Path[3] | byte (4) | Derivation Path Data      | ?          |
| Path[4] | byte (4) | Derivation Path Data      | ?          |

#### Response

| Field          | Type      | Content              | Note                     |
| -------------- | --------- | -------------------- | ------------------------ |
| PK             | byte (65) | Public Key           |                          |
| ADDR_RAW_LEN   | byte (1)  | ADDR_RAW Length      |                          |
| ADDR_RAW       | byte (??) | Address as Raw Bytes |                          |
| ADDR_HUMAN_LEN | byte (1)  | ADDR_HUMAN Len       |                          |
| ADDR_HUMAN     | byte (??) | Address as String    |                          |
| SW1-SW2        | byte (2)  | Return code          | see list of return codes |

---

### INS_GET_ADDR_MULTISIG

Derives and (optionally) displays a Stacks **multisig (P2SH) address** for
on-device verification. The device derives its own public key from the supplied
path and splices it into the ordered cosigner set at `device_key_index`, builds
the Bitcoin-style multisig redeem script (`OP_m · (len·pubkey)ⁿ · OP_n ·
OP_CHECKMULTISIG`), takes `Hash160 = RIPEMD160(SHA256(script))`, and c32-encodes
it with the multisig version byte.

Supports both **sequential P2SH** (`0x01`) and **non-sequential P2SH** (`0x05`)
hash modes — they derive the same address and differ only in transaction
signing — with **compressed** cosigner public keys, up to the protocol maximum
of `n ≤ 15` (the 520-byte redeem-script limit).

Larger key sets exceed a single APDU, so the command uses **chunked transport**
(like signing): `P1` is the chunk type and `P2` is `0`. The **INIT** chunk carries
the device path; the **ADD/LAST** chunks carry the multisig header and cosigner
keys. The c32 version byte and the confirm flag travel in the payload header.

#### Command — INIT chunk (P1 = 0x00)

| Field | Type      | Content                                | Expected |
| ----- | --------- | -------------------------------------- | -------- |
| CLA   | byte (1)  | Application Identifier                  | 0x09     |
| INS   | byte (1)  | Instruction ID                         | 0x07     |
| P1    | byte (1)  | Chunk type = INIT                      | 0x00     |
| P2    | byte (1)  | Unused                                 | 0x00     |
| Path  | byte (20) | Device derivation path (5 × 4-byte LE) |          |

#### Command — ADD / LAST chunks (P1 = 0x01 / 0x02)

The following payload is concatenated across the ADD/LAST chunks (split at 250 bytes):

| Field          | Type      | Content                                   | Expected                    |
| -------------- | --------- | ----------------------------------------- | --------------------------- |
| P1             | byte (1)  | Chunk type = ADD (0x01) / LAST (0x02)     |                             |
| P2             | byte (1)  | Unused                                     | 0x00                        |
| Confirm        | byte (1)  | Request user confirmation                  | No = 0, Yes = 1             |
| Version        | byte (1)  | c32 multisig version byte                  | 20 (mainnet) / 21 (testnet) |
| HashMode       | byte (1)  | Multisig hash mode                         | 0x01 (P2SH) / 0x05 (non-seq)|
| m              | byte (1)  | Required signatures (threshold)            | 1 ≤ m ≤ n                   |
| n              | byte (1)  | Total participating keys                   | 1 ≤ n ≤ 15                  |
| DeviceKeyIndex | byte (1)  | Position of this device's key in the set   | 0 ≤ index < n               |
| CosignerKeys   | byte (?)  | (n-1) × 33-byte compressed cosigner pubkeys, in order, excluding the device slot | |

#### Response (on the LAST chunk)

| Field          | Type      | Content                  | Note                     |
| -------------- | --------- | ------------------------ | ------------------------ |
| PK             | byte (33) | This device's public key |                          |
| ADDR_HUMAN     | byte (??) | Multisig address string  | c32-encoded (SM…/SN…)    |
| SW1-SW2        | byte (2)  | Return code              | see list of return codes |

#### Return codes

| Return code | Chunk     | Cause                                                                                                  |
| ----------- | --------- | ------------------------------------------------------------------------------------------------------ |
| 0x9000      | any       | INIT/ADD accepted; on LAST, the public key and address follow (after approval when Confirm = 1)        |
| 0x6700      | INIT      | The path is shorter than 20 bytes                                                                      |
| 0x6700      | LAST      | The payload is shorter than the 6-byte header, or longer or shorter than 6 + (n-1) × 33 bytes          |
| 0x6983      | ADD, LAST | The payload overflows the reassembly buffer                                                            |
| 0x6984      | INIT      | The path is not `44'/5757'/...`, `5757'/...` or `44'/1'/...`                                           |
| 0x6984      | LAST      | Version, HashMode, m, n or DeviceKeyIndex is out of range, or the address could not be derived        |
| 0x6986      | any       | A review is on screen or the PIN is not validated; on LAST, also when the user rejects the address    |
| 0x6987      | ADD, LAST | No INIT was sent first, or the transfer was opened by another INS                                      |
| 0x6B00      | any       | P2 is not 0, or P1 is not INIT, ADD or LAST                                                            |

#### Notes

- The device deriving its own key (rather than trusting a host-supplied one)
  guarantees the displayed multisig address actually includes this device.
- Key order matters for P2SH (both sequential and non-sequential): the cosigner
  keys must be supplied in the exact order they occupy in the multisig, omitting
  the device's own slot.
- Follow-ups: P2WSH / P2WSH-non-sequential hash modes and uncompressed keys.

---

### INS_GET_AUTH_PUBKEY

#### Command

| Field | Type     | Content                | Expected          |
| ----- | -------- | ---------------------- | ----------------- |
| CLA   | byte (1) | Application Identifier | 0x09              |
| INS   | byte (1) | Instruction ID         | 0x03              |
| P1    | byte (1) | Retrieval mode         | 0 (Only retrieve) |
| P2    | byte (1) | Parameter 2            | 0 (ignored)       |
| L     | byte (1) | Bytes in payload       | (depends)         |
| Path  | byte (?) | Derivation Path Data   | (see below)       |

##### Derivation Path

- Starts with "m"
- Can be either 6 or 4 levels deep
- For 6 levels: "m/44'/5757'/5'/0/3"
- For 4 levels (Identity): "m/888'/0'/<account>"
- Each level is serialized as a 4-byte little-endian unsigned integer
- Hardened levels (with ') have 0x80000000 added to their value

#### Response

| Field     | Type      | Content           | Note               |
| --------- | --------- | ----------------- | ------------------ |
| publicKey | byte (??) | Public Key        |                    |
| address   | byte (??) | Address as String |                    |
| SW1-SW2   | byte (2)  | Return code       | 0x9000 for success |

#### Processing

1. The command is sent with the serialized derivation path as payload.
2. The device derives the public key and address for the given path.
3. The device returns the public key and address in the response.

#### Notes

- The CLA (0x09) is specific to this application.
- The INS (0x03) identifies this as a GET_AUTH_PUBKEY operation.
- P1 is set to 0, indicating "only retrieve" mode.
- P2 is ignored in this command.
- The expected successful return code is 0x9000.
- In case of an error, the response will include a return code and an error message instead of the public key and address.

---

### INS_SIGN_SECP256K1

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0x09      |
| INS   | byte (1) | Instruction ID         | 0x02      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

_First Packet_

| Field   | Type     | Content              | Expected   |
| ------- | -------- | -------------------- | ---------- |
| Path[0] | byte (4) | Derivation Path Data | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data | 0x8000167d |
| Path[2] | byte (4) | Derivation Path Data | ?          |
| Path[3] | byte (4) | Derivation Path Data | ?          |
| Path[4] | byte (4) | Derivation Path Data | ?          |

_Other Chunks/Packets_

| Field | Type     | Content | Expected |
| ----- | -------- | ------- | -------- |
| Data  | bytes... | Message |          |

Data is defined as:

| Field   | Type    | Content      | Expected |
| ------- | ------- | ------------ | -------- |
| Message | bytes.. | Data to sign |          |

#### Response

| Field       | Type            | Content     | Note                     |
| ----------- | --------------- | ----------- | ------------------------ |
| secp256k1 R | byte (32)       | Signature   |                          |
| secp256k1 S | byte (32)       | Signature   |                          |
| secp256k1 V | byte (1)        | Signature   |                          |
| SIG         | byte (variable) | Signature   | DER format               |
| SW1-SW2     | byte (2)        | Return code | see list of return codes |

#### Return codes

| Return code | Chunk     | Cause                                                                                                           |
| ----------- | --------- | --------------------------------------------------------------------------------------------------------------- |
| 0x9000      | any       | INIT/ADD accepted; on LAST, the signature follows once the user approves                                       |
| 0x6700      | INIT      | The path is shorter than 20 bytes                                                                               |
| 0x6983      | ADD, LAST | The payload overflows the reassembly buffer                                                                     |
| 0x6984      | INIT      | The path is not `44'/5757'/...`, `5757'/...` or `44'/1'/...`                                                    |
| 0x6984      | LAST      | The payload does not parse or validate (the error message follows as ASCII), or the user dismissed the blind-signing screen |
| 0x6986      | any       | A review is on screen or the PIN is not validated; on LAST, also when the user rejects                         |
| 0x6987      | ADD, LAST | No INIT was sent first, or the transfer was opened by another INS                                               |
| 0x6B00      | any       | P2 is not 0, or P1 is not INIT, ADD or LAST                                                                     |
| 0x6F01      | LAST      | The signing hash or the signature could not be computed after approval                                          |

### INS_SIGN_JWT_SECP256K1

#### Command

| Field   | Type     | Content                | Expected                         |
| ------- | -------- | ---------------------- | -------------------------------- |
| CLA     | byte (1) | Application Identifier | 0x09                             |
| INS     | byte (1) | Instruction ID         | 0x04                             |
| P1      | byte (1) | Payload desc           | 0 = init, 1 = add, 2 = last      |
| P2      | byte (1) | ----                   | 0                                |
| L       | byte (1) | Bytes in payload       | (depends)                        |
| Path    | byte (?) | Derivation Path Data   | INIT chunk only (see below)      |
| Message | byte (?) | JWT message to sign    | ADD/LAST chunks (variable)       |

##### Derivation Path

- Starts with "m"
- Can be either 6 or 4 levels deep
- For 6 levels: "m/44'/5757'/5'/0/3"
- For 4 levels (Identity): "m/888'/0'/<account>"
- Each level is serialized as a 4-byte little-endian unsigned integer
- Hardened levels (with ') have 0x80000000 added to their value

#### Response

| Field            | Type      | Content               | Note                     |
| ---------------- | --------- | --------------------- | ------------------------ |
| returnCode       | byte (2)  | Return code           | see list of return codes |
| errorMessage     | byte (??) | Error message string  | Optional                 |
| postSignHash     | byte (32) | Hash after signing    | Optional                 |
| signatureCompact | byte (65) | Compact signature     | Optional                 |
| signatureDER     | byte (??) | DER-encoded signature | Optional                 |

#### Processing

1. The message is split into chunks of up to 250 bytes each.
2. Each chunk is sent in a separate APDU command.
3. The first chunk (P1 = 0, INIT) carries only the derivation path, `m/888'/0'/<account>`.
4. The message follows in ADD chunks (P1 = 1) and ends with one LAST chunk (P1 = 2). P2 is 0 on every chunk.
5. The device processes all chunks and returns the final result.
6. Return codes are those of INS_SIGN_SECP256K1, except that the path on the INIT chunk must be the identity path above (0x6984 otherwise).

#### Notes

- The CLA (0x09) is specific to this application.
- The INS (0x04) identifies this as a INS_SIGN_JWT_SECP256K1 operation.
- The message length is determined by the total payload across all chunks.
- Error responses may not include all fields of the success response.

---

### INS_GET_MASTER_KEY_FINGERPRINT

Returns the BIP32 master key fingerprint (first 4 bytes of RIPEMD160(SHA256(master_public_key))).

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x09     |
| INS   | byte (1) | Instruction ID         | 0x06     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field       | Type     | Content                   | Note                     |
| ----------- | -------- | ------------------------- | ------------------------ |
| FINGERPRINT | byte (4) | Master key fingerprint    | BIP32 fingerprint        |
| SW1-SW2     | byte (2) | Return code               | see list of return codes |

#### Notes

- The fingerprint is calculated as: first 4 bytes of RIPEMD160(SHA256(master_public_key))
- This follows the BIP32 standard for key fingerprints
- Requires PIN to be validated before execution
