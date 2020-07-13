import Transport from "@ledgerhq/hw-transport";

export interface ResponseBase {
  errorMessage: string;
  returnCode: number;
}

export interface ResponseAddress extends ResponseBase {
  publicKey: string;
  address: string;
}

export interface ResponseVersion extends ResponseBase {
  testMode: boolean;
  major: number;
  minor: number;
  patch: number;
  deviceLocked: boolean;
  targetId: string;
}

export interface ResponseAppInfo extends ResponseBase {
  appName: string;
  appVersion: string;
  flagLen: number;
  flagsValue: number;
  flagRecovery: boolean;
  flagSignedMcuCode: boolean;
  flagOnboarded: boolean;
  flagPINValidated: boolean;
}

export interface ResponseSign extends ResponseBase {
  signatureCompact: Buffer;
  signatureDER: Buffer;
}

export interface BlockstackApp {
  new(transport: Transport): BlockstackApp;

  getVersion(): Promise<ResponseVersion>;
  getAppInfo(): Promise<ResponseAppInfo>;
  getAddressAndPubKey(path: string): Promise<ResponseAddress>;
  showAddressAndPubKey(path: string): Promise<ResponseAddress>;

  sign(path: string, message: Buffer): Promise<ResponseSign>;
}
