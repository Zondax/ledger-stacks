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

| Return code | Description             |
| ----------- | ----------------------- |
| 0x6400      | Execution Error         |
| 0x6982      | Empty buffer            |
| 0x6983      | Output buffer too small |
| 0x6986      | Command not allowed     |
| 0x6D00      | INS not supported       |
| 0x6E00      | CLA not supported       |
| 0x6F00      | Unknown                 |
| 0x9000      | Success                 |

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

### INS_SIGN_JWT_SECP256K1

#### Command

| Field   | Type     | Content                | Expected    |
| ------- | -------- | ---------------------- | ----------- |
| CLA     | byte (1) | Application Identifier | 0x09        |
| INS     | byte (1) | Instruction ID         | 0x04        |
| P1      | byte (1) | Chunk index            | 1 to N      |
| P2      | byte (1) | Total chunks           | N           |
| L       | byte (1) | Bytes in payload       | (depends)   |
| Path    | byte (?) | Derivation Path Data   | (see below) |
| Message | byte (?) | JWT message to sign    | (variable)  |

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
3. P1 indicates the current chunk index (starting from 1).
4. P2 indicates the total number of chunks.
5. The first chunk includes the derivation path.
6. Subsequent chunks only contain message data.
7. The device processes all chunks and returns the final result.

#### Notes

- The CLA (0x09) is specific to this application.
- The INS (0x04) identifies this as a INS_SIGN_JWT_SECP256K1 operation.
- The message length is determined by the total payload across all chunks.
- Error responses may not include all fields of the success response.

---

### INS_GET_MASTER_KEY_FINGERPRINT

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x09     |
| INS   | byte (1) | Instruction ID         | 0x06     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field       | Type     | Content                | Note                     |
| ----------- | -------- | ---------------------- | ------------------------ |
| FINGERPRINT | byte (4) | Master Key Fingerprint | 4-byte fingerprint       |
| SW1-SW2     | byte (2) | Return code            | see list of return codes |

#### Notes

- The CLA (0x09) is specific to this application.
- The INS (0x06) identifies this as a GET_MASTER_KEY_FINGERPRINT operation.
- No payload is required for this command.
- The fingerprint is calculated as the first 4 bytes of the RIPEMD160(SHA256(master_public_key)).
