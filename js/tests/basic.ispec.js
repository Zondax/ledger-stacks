/* eslint-disable no-console */
import BlockstackApp from "index.js";
import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import { expect, test } from "jest";
import { ERROR_CODE, PKLEN } from "../src/common";

const test_path = "m/44'/5757'/5'/0'/3'";

test("get version", async () => {
  const transport = await TransportNodeHid.create();
  try {
    const app = new BlockstackApp(transport);
    const resp = await app.getVersion();
    // eslint-disable-next-line no-console
    console.log(resp);

    expect(resp.return_code).toEqual(ERROR_CODE.NoError);
    expect(resp.error_message).toEqual("No errors");
    expect(resp).toHaveProperty("test_mode");
    expect(resp).toHaveProperty("major");
    expect(resp).toHaveProperty("minor");
    expect(resp).toHaveProperty("patch");
    expect(resp.test_mode).toEqual(false);
  } finally {
    transport.close();
  }
});

test("appInfo", async () => {
  const transport = await TransportNodeHid.create();
  try {
    const app = new BlockstackApp(transport);

    const resp = await app.appInfo();

    // eslint-disable-next-line no-console
    console.log(resp);

    expect(resp.return_code).toEqual(ERROR_CODE.NoError);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("appName");
    expect(resp).toHaveProperty("appVersion");
    expect(resp).toHaveProperty("flagLen");
    expect(resp).toHaveProperty("flagsValue");
    expect(resp).toHaveProperty("flag_recovery");
    expect(resp).toHaveProperty("flag_signed_mcu_code");
    expect(resp).toHaveProperty("flag_onboarded");
    expect(resp).toHaveProperty("flag_pin_validated");
  } finally {
    transport.close();
  }
});

test("deviceInfo", async () => {
  const transport = await TransportNodeHid.create();
  try {
    const app = new BlockstackApp(transport);

    const resp = await app.deviceInfo();

    // eslint-disable-next-line no-console
    console.log(resp);

    expect(resp.return_code).toEqual(ERROR_CODE.NoError);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("targetId");
    expect(resp).toHaveProperty("seVersion");
    expect(resp).toHaveProperty("flag");
    expect(resp).toHaveProperty("mcuVersion");
  } finally {
    transport.close();
  }
});

test("getAddressAndPubKeyUnshielded", async () => {
  const transport = await TransportNodeHid.create();
  try {
    const app = new BlockstackApp(transport);

    const resp = await app.getAddressAndPubKey(test_path, true);

    // eslint-disable-next-line no-console
    console.log(resp);

    expect(resp.return_code).toEqual(ERROR_CODE.NoError);
    expect(resp.error_message).toEqual("No errors");

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("address_raw");
    expect(resp).toHaveProperty("address");

    expect(resp.address_raw.toString("hex")).toEqual("");

    expect(resp.address).toEqual("");
  } finally {
    transport.close();
  }
});

test("showAddressAndPubKeyUnshielded", async () => {
  // noinspection ES6ModulesDependencies
  jest.setTimeout(60000);
  const transport = await TransportNodeHid.create();
  try {
    const app = new BlockstackApp(transport);

    const resp = await app.showAddressAndPubKey(test_path, true);

    // eslint-disable-next-line no-console
    console.log(resp);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("address_raw");
    expect(resp).toHaveProperty("address");

    expect(resp.address_raw.toString("hex")).toEqual("");

    expect(resp.address).toEqual("");
  } finally {
    transport.close();
  }
});
