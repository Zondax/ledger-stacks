/** ******************************************************************************
 *  (c) 2019-2022 Zondax AG
 *  (c) 2016-2017 Ledger
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
import Transport from '@ledgerhq/hw-transport';
import { serializePath } from './helper';
import { ResponseAddress, ResponseAppInfo, /* ResponseMasterFingerprint, */ ResponseSign, ResponseVersion } from './types';
import {
  CHUNK_SIZE,
  CLA,
  errorCodeToString,
  getVersion,
  INS,
  LedgerError,
  P1_VALUES,
  PAYLOAD_TYPE,
  PKLEN,
  processErrorResponse,
} from './common';
import { encode } from 'varuint-bitcoin';

import type { AddressVersion } from '@stacks/transactions';

export { LedgerError };
export * from './types';

function processGetAddrResponse(response: Buffer) {
  let partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const publicKey = Buffer.from(partialResponse.slice(0, PKLEN));
  partialResponse = partialResponse.slice(PKLEN);

  const address = Buffer.from(partialResponse.slice(0, -2)).toString();

  return {
    publicKey,
    address,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

export default class StacksApp {
  transport;

  constructor(transport: Transport) {
    this.transport = transport;
    if (!transport) {
      throw new Error('Transport has not been defined');
    }
  }

  static prepareChunks(serializedPathBuffer: Buffer, message: Buffer) {
    const chunks = [];

    // First chunk (only path)
    chunks.push(serializedPathBuffer);

    const messageBuffer = Buffer.from(message);

    const buffer = Buffer.concat([messageBuffer]);
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.slice(i, end));
    }

    return chunks;
  }

  async signGetChunks(path: string, message: Buffer) {
    return StacksApp.prepareChunks(serializePath(path), message);
  }

  async getVersion(): Promise<ResponseVersion> {
    return getVersion(this.transport).catch(err => processErrorResponse(err));
  }

  async getAppInfo(): Promise<ResponseAppInfo> {
    return this.transport.send(0xb0, 0x01, 0, 0).then(response => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      const result: { errorMessage?: string; returnCode?: LedgerError } = {};

      let appName = 'err';
      let appVersion = 'err';
      let flagLen = 0;
      let flagsValue = 0;

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        result.errorMessage = 'response format ID not recognized';
        result.returnCode = LedgerError.DeviceIsBusy;
      } else {
        const appNameLen = response[1];
        appName = response.slice(2, 2 + appNameLen).toString('ascii');
        let idx = 2 + appNameLen;
        const appVersionLen = response[idx];
        idx += 1;
        appVersion = response.slice(idx, idx + appVersionLen).toString('ascii');
        idx += appVersionLen;
        const appFlagsLen = response[idx];
        idx += 1;
        flagLen = appFlagsLen;
        flagsValue = response[idx];
      }

      return {
        returnCode,
        errorMessage: errorCodeToString(returnCode),
        //
        appName,
        appVersion,
        flagLen,
        flagsValue,
        flagRecovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flagSignedMcuCode: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flagOnboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flagPINValidated: (flagsValue & 128) !== 0,
      };
    }, processErrorResponse);
  }

  async getAddressAndPubKey(path: string, version: AddressVersion): Promise<ResponseAddress> {
    const serializedPath = serializePath(path);
    return this.transport
      .send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.ONLY_RETRIEVE, version, serializedPath, [0x9000])
      .then(processGetAddrResponse, processErrorResponse);
  }

  async getIdentityPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path);
    return this.transport
      .send(CLA, INS.GET_AUTH_PUBKEY, P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [0x9000])
      .then(processGetAddrResponse, processErrorResponse);
  }

  /*
  async getMasterFingerprint(): Promise<ResponseMasterFingerprint> {
    return this.transport
      .send(CLA, INS.GET_MASTER_FINGERPRINT, 0, 0, Buffer.alloc(0), [LedgerError.NoErrors])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

        if (returnCode !== LedgerError.NoErrors) {
          return {
            returnCode,
            errorMessage: errorCodeToString(returnCode),
            fingerprint: Buffer.alloc(0),
          };
        }

        const fingerprint = response.slice(0, 4); // Master fingerprint is 4 bytes

        return {
          returnCode,
          errorMessage: errorCodeToString(returnCode),
          fingerprint,
        };
      }, processErrorResponse);
  }
  */

  async showAddressAndPubKey(path: string, version: AddressVersion): Promise<ResponseAddress> {
    const serializedPath = serializePath(path);
    return this.transport
      .send(
        CLA,
        INS.GET_ADDR_SECP256K1,
        P1_VALUES.SHOW_ADDRESS_IN_DEVICE,
        version,
        serializedPath,
        [LedgerError.NoErrors]
      )
      .then(processGetAddrResponse, processErrorResponse);
  }

  async signSendChunk(
    chunkIdx: number,
    chunkNum: number,
    chunk: Buffer,
    ins: number
  ): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }

    return this.transport
      .send(CLA, ins, payloadType, 0, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);
        let errorDescription = '';

        let postSignHash = Buffer.alloc(0);
        let signatureCompact = Buffer.alloc(0);
        let signatureVRS = Buffer.alloc(0);
        let signatureDER = Buffer.alloc(0);

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response
            .slice(0, response.length - 2)
            .toString('ascii')}`;
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          postSignHash = response.slice(0, 32);
          signatureCompact = response.slice(32, 97);
          signatureVRS = Buffer.alloc(65);
          signatureVRS[0] = signatureCompact[signatureCompact.length - 1];
          Buffer.from(signatureCompact).copy(signatureVRS, 1, 0, 64);
          signatureDER = response.slice(97, response.length - 2);
          return {
            postSignHash,
            signatureCompact,
            signatureVRS,
            signatureDER,
            returnCode: returnCode,
            errorMessage: errorMessage,
          };
        }

        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
        };
      }, processErrorResponse);
  }

  async sign(path: string, message: Buffer) {
    return this.signGetChunks(path, message).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_SECP256K1).then(
        async response => {
          let result = {
            returnCode: response.returnCode,
            errorMessage: response.errorMessage,
            postSignHash: null as null | Buffer,
            signatureCompact: null as null | Buffer,
            signatureDER: null as null | Buffer,
          };
          for (let i = 1; i < chunks.length; i += 1) {
            // eslint-disable-next-line no-await-in-loop
            result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_SECP256K1);
            if (result.returnCode !== LedgerError.NoErrors) {
              break;
            }
          }
          return result;
        },
        processErrorResponse
      );
    }, processErrorResponse);
  }

  async sign_msg(path: string, message: string) {
    const len = encode(message.length);
    const stacks_message = '\x17Stacks Signed Message:\n';
    const blob = Buffer.concat([Buffer.from(stacks_message), len, Buffer.from(message)]);
    const ins = INS.SIGN_SECP256K1;
    return this.signGetChunks(path, blob).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], ins).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          postSignHash: null as null | Buffer,
          signatureCompact: null as null | Buffer,
          signatureDER: null as null | Buffer,
        };
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], ins);
          if (result.returnCode !== LedgerError.NoErrors) {
            break;
          }
        }
        return result;
      }, processErrorResponse);
    }, processErrorResponse);
  }

  async sign_jwt(path: string, message: string) {
    const len = message.length;
    const blob = Buffer.from(message);
    const ins = INS.SIGN_JWT_SECP256K1;
    return this.signGetChunks(path, blob).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], ins).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          postSignHash: null as null | Buffer,
          signatureCompact: null as null | Buffer,
          signatureDER: null as null | Buffer,
        };
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], ins);
          if (result.returnCode !== LedgerError.NoErrors) {
            break;
          }
        }
        return result;
      }, processErrorResponse);
    }, processErrorResponse);
  }

  async sign_structured_msg(path: string, domain: string, message: string) {
    const len = encode(message.length);
    const header = 'SIP018';
    const blob = Buffer.concat([Buffer.from(header), Buffer.from(domain, 'hex'), Buffer.from(message, 'hex')]);
    const ins = INS.SIGN_SECP256K1;
    return this.signGetChunks(path, blob).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], ins).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          postSignHash: null as null | Buffer,
          signatureCompact: null as null | Buffer,
          signatureDER: null as null | Buffer,
        };
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], ins);
          if (result.returnCode !== LedgerError.NoErrors) {
            break;
          }
        }
        return result;
      }, processErrorResponse);
    }, processErrorResponse);
  }

}
