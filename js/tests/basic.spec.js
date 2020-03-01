/* eslint-disable no-console */
import blake2 from "blake2";
import secp256k1 from "secp256k1/elliptic";
import { expect, test } from "./jest";
import { getCID, getDigest } from "./utils";
import { serializePathv1 } from "../src/helperV1";

test("serializePathv1", async () => {
  const path = "m/44'/461'/0/0/5";
  const buf = Buffer.alloc(20);
  buf.writeUInt32LE(0x80000000 + 44, 0);
  buf.writeUInt32LE(0x80000000 + 461, 4);
  buf.writeUInt32LE(0, 8);
  buf.writeUInt32LE(0, 12);
  buf.writeUInt32LE(5, 16);

  const bufPath = serializePathv1(path);

  expect(bufPath).toEqual(buf);
});

test("serializePathv1 should be a string", async () => {
  const path = [44, 461, 0, 2, 3];

  expect(() => {
    serializePathv1(path);
  }).toThrowError(/Path should be a string/);
});

test("serializePathv1 doesn't start with 'm'", async () => {
  const path = "/44'/461'/0/0/5";

  expect(() => {
    serializePathv1(path);
  }).toThrowError(/Path should start with "m"/);
});

test("serializePathv1 length needs to be 5", async () => {
  const path = "m/44'/461'/0/0";

  expect(() => {
    serializePathv1(path);
  }).toThrowError(/Invalid path/);
});

test("serializePathv1 invalid number", async () => {
  const path = "m/44'/461'/0/0/l";

  expect(() => {
    serializePathv1(path);
  }).toThrowError(/Invalid path : l is not a number/);
});

test("serializePathv1 bigger than 0x80000000", async () => {
  const path = "m/44'/461'/0/0/2147483648";

  expect(() => {
    serializePathv1(path);
  }).toThrowError("Incorrect child value (bigger or equal to 0x80000000)");
});

test("serializePathv1 bigger than 0x80000000", async () => {
  const path = "m/44'/461'/0/0/2147483649";

  expect(() => {
    serializePathv1(path);
  }).toThrowError("Incorrect child value (bigger or equal to 0x80000000)");
});
