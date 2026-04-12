import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encode as encodeCbor } from "cbor-x";

import {
  ExternalSignatureSdkError,
  GOOGLE_CLIENT_DATA_JSON_EXTRA_VALUE,
  PublicKey,
  buildExecuteInstructions,
  createExecuteInstructionsChallenge,
  createInitializePasskeyChallenge,
  createSecp256r1Instruction,
  truncateSlot,
} from "../dist/index.js";
import { toLittleEndianU64 } from "../dist/bytes.js";
import {
  decodeSpkiP256PublicKey,
  fromBase64Url,
  parseClientDataJsonReconstructionParams,
  parseDerSignatureToCompact,
  parseRegistrationCredential,
  toBase64Url,
} from "../dist/webauthn.js";

const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const SDK_DIR = "/Users/orion/Documents/GitHub/external-signature-program/sdks/ts-sdk";
const DIST_INDEX = path.join(SDK_DIR, "dist/index.js");
const DIST_WEBAUTHN = path.join(SDK_DIR, "dist/webauthn.js");
const TSC_BIN = path.join(SDK_DIR, "node_modules/.bin/tsc");

function hexToBytes(hex) {
  return Uint8Array.from(hex.match(/.{1,2}/g).map((part) => Number.parseInt(part, 16)));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function bigIntToMinimalBytes(value) {
  if (value === 0n) return Uint8Array.of(0x00);
  const out = [];
  let current = value;
  while (current > 0n) {
    out.unshift(Number(current & 0xffn));
    current >>= 8n;
  }
  return Uint8Array.from(out);
}

function encodeDerInteger(value) {
  let bytes = bigIntToMinimalBytes(value);
  if ((bytes[0] & 0x80) !== 0) {
    bytes = Uint8Array.of(0x00, ...bytes);
  }
  return Uint8Array.of(0x02, bytes.length, ...bytes);
}

function encodeDerSignature(r, s) {
  const rDer = encodeDerInteger(r);
  const sDer = encodeDerInteger(s);
  return Uint8Array.of(0x30, rDer.length + sDer.length, ...rDer, ...sDer);
}

function createP256Spki(uncompressedPoint) {
  const algorithmIdentifier = Uint8Array.of(
    0x30,
    0x13,
    0x06,
    0x07,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x03,
    0x01,
    0x07,
  );
  const subjectPublicKey = Uint8Array.of(
    0x03,
    1 + uncompressedPoint.length,
    0x00,
    ...uncompressedPoint,
  );
  return Uint8Array.of(
    0x30,
    algorithmIdentifier.length + subjectPublicKey.length,
    ...algorithmIdentifier,
    ...subjectPublicKey,
  );
}

function createCoseP256PublicKey(x, y, overrides = {}) {
  return encodeCbor(
    new Map([
      [1, overrides.kty ?? 2],
      [3, overrides.alg ?? -7],
      [-1, overrides.crv ?? 1],
      [-2, overrides.x ?? x],
      [-3, overrides.y ?? y],
    ]),
  );
}

function createRegistrationAuthData({
  x,
  y,
  credentialId = Uint8Array.of(0x01, 0x02, 0x03),
  flags = 0x41,
  rpIdHash = new Uint8Array(32),
  signCount = 0,
  aaguid = new Uint8Array(16),
  coseOverrides,
  trailingBytes = new Uint8Array(),
}) {
  const coseKey = createCoseP256PublicKey(x, y, coseOverrides);
  return Uint8Array.of(
    ...rpIdHash,
    flags,
    (signCount >>> 24) & 0xff,
    (signCount >>> 16) & 0xff,
    (signCount >>> 8) & 0xff,
    signCount & 0xff,
    ...aaguid,
    (credentialId.length >>> 8) & 0xff,
    credentialId.length & 0xff,
    ...credentialId,
    ...coseKey,
    ...trailingBytes,
  );
}

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function createRegistrationCredential({ authData, signature, clientDataJSON, publicKeySpki }) {
  const attestationObject = encodeCbor({
    authData,
    attStmt: signature == null ? {} : { sig: signature },
  });

  return {
    rawId: toArrayBuffer(Uint8Array.of(0x01, 0x02, 0x03)),
    response: {
      attestationObject: toArrayBuffer(attestationObject),
      clientDataJSON: toArrayBuffer(clientDataJSON),
      getPublicKey:
        publicKeySpki == null
          ? undefined
          : () => toArrayBuffer(publicKeySpki),
    },
  };
}

function runTsc({ source, lib }) {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), "external-signature-ts-sdk-"));
  const entryPath = path.join(tempDir, "consumer.ts");
  writeFileSync(entryPath, source, "utf8");
  execFileSync(
    TSC_BIN,
    [
      "--target",
      "ES2022",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--strict",
      "--noEmit",
      "--lib",
      lib,
      "--types",
      "node",
      entryPath,
    ],
    { cwd: SDK_DIR, stdio: "pipe" },
  );
}

test("parseDerSignatureToCompact returns fixed 64-byte compact signature", () => {
  const signature = encodeDerSignature(1n, 2n);
  const compact = parseDerSignatureToCompact(signature);

  assert.equal(compact.length, 64);
  assert.equal(bytesToHex(compact.slice(0, 32)), `${"0".repeat(63)}1`);
  assert.equal(bytesToHex(compact.slice(32)), `${"0".repeat(63)}2`);
});

test("parseDerSignatureToCompact normalizes high-s values", () => {
  const signature = encodeDerSignature(5n, P256_ORDER - 1n);
  const compact = parseDerSignatureToCompact(signature);

  assert.equal(bytesToHex(compact.slice(0, 32)), `${"0".repeat(63)}5`);
  assert.equal(bytesToHex(compact.slice(32)), `${"0".repeat(63)}1`);
});

test("parseDerSignatureToCompact rejects malformed/canonical DER violations", () => {
  const withTrailingBytes = Uint8Array.of(...encodeDerSignature(1n, 2n), 0x00);
  const nonCanonicalLeadingZero = Uint8Array.of(
    0x30,
    0x07,
    0x02,
    0x02,
    0x00,
    0x01,
    0x02,
    0x01,
    0x02,
  );

  assert.throws(() => parseDerSignatureToCompact(withTrailingBytes), ExternalSignatureSdkError);
  assert.throws(
    () => parseDerSignatureToCompact(nonCanonicalLeadingZero),
    ExternalSignatureSdkError,
  );
  assert.throws(() => parseDerSignatureToCompact(encodeDerSignature(0n, 1n)), ExternalSignatureSdkError);
  assert.throws(
    () => parseDerSignatureToCompact(encodeDerSignature(1n, P256_ORDER)),
    ExternalSignatureSdkError,
  );
});

test("parseClientDataJsonReconstructionParams validates type and origin", () => {
  const textEncoder = new TextEncoder();

  const validCreate = textEncoder.encode(
    JSON.stringify({
      type: "webauthn.create",
      challenge: "x",
      origin: "https://example.com",
      crossOrigin: false,
    }),
  );
  const validGet = textEncoder.encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: "x",
      origin: "http://localhost:8080",
      crossOrigin: true,
      other_keys_can_be_added_here: GOOGLE_CLIENT_DATA_JSON_EXTRA_VALUE,
    }),
  );

  const createParams = parseClientDataJsonReconstructionParams(validCreate);
  const getParams = parseClientDataJsonReconstructionParams(validGet);

  assert.equal(createParams.typeAndFlags, 0x00);
  assert.equal(createParams.port, null);
  assert.equal(getParams.typeAndFlags, 0x17);
  assert.equal(getParams.port, 8080);

  const unknownType = textEncoder.encode(
    JSON.stringify({
      type: "webauthn.something-else",
      challenge: "x",
      origin: "https://example.com",
    }),
  );
  const invalidOrigin = textEncoder.encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: "x",
      origin: "ftp://example.com",
    }),
  );

  assert.throws(() => parseClientDataJsonReconstructionParams(unknownType), ExternalSignatureSdkError);
  assert.throws(() => parseClientDataJsonReconstructionParams(invalidOrigin), ExternalSignatureSdkError);
});

test("parseClientDataJsonReconstructionParams rejects non-canonical google extra and non-boolean crossOrigin", () => {
  const textEncoder = new TextEncoder();
  const nonCanonicalGoogleExtra = textEncoder.encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: "x",
      origin: "https://example.com",
      other_keys_can_be_added_here: "some other value",
    }),
  );
  const invalidCrossOrigin = textEncoder.encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: "x",
      origin: "https://example.com",
      crossOrigin: "false",
    }),
  );

  assert.throws(
    () => parseClientDataJsonReconstructionParams(nonCanonicalGoogleExtra),
    ExternalSignatureSdkError,
  );
  assert.throws(
    () => parseClientDataJsonReconstructionParams(invalidCrossOrigin),
    ExternalSignatureSdkError,
  );
});

test("base64url helpers roundtrip in Node runtime", () => {
  const bytes = Uint8Array.of(0, 1, 2, 253, 254, 255);
  const encoded = toBase64Url(bytes);

  assert.equal(encoded, "AAEC_f7_");
  assert.deepEqual(fromBase64Url(encoded), bytes);
  assert.throws(() => fromBase64Url("this-is-not-valid%%%"), ExternalSignatureSdkError);
});

test("createSecp256r1Instruction uses canonical inline precompile offsets", () => {
  const signature = encodeDerSignature(1n, 2n);
  const message = Uint8Array.of(0xaa, 0xbb, 0xcc);
  const publicKey = Uint8Array.of(0x02, ...new Array(32).fill(0x11));

  const ix = createSecp256r1Instruction({ signature, message, publicKey });
  const data = Uint8Array.from(ix.data);

  assert.equal(data[0], 1);
  assert.equal(data[4], 0xff);
  assert.equal(data[5], 0xff);
  assert.equal(data[8], 0xff);
  assert.equal(data[9], 0xff);
  assert.equal(data[14], 0xff);
  assert.equal(data[15], 0xff);
  assert.equal(bytesToHex(data.slice(16, 49)), bytesToHex(publicKey));

  const tooLargeMessage = new Uint8Array(65536);
  assert.throws(
    () => createSecp256r1Instruction({ signature, message: tooLargeMessage, publicKey }),
    ExternalSignatureSdkError,
  );
});

test("challenge and wrapped instruction serialization vectors are stable", () => {
  const nonceSigner = new PublicKey("11111111111111111111111111111111");
  const recentSlotHash = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  const executeChallenge = createExecuteInstructionsChallenge({
    nonceSigner,
    recentSlotHash,
    instructions: [],
  });
  const initializeChallenge = createInitializePasskeyChallenge({
    payer: nonceSigner,
    recentSlotHash,
  });

  assert.equal(
    bytesToHex(executeChallenge.challenge),
    "33807114e3dd95a85615155857994b11f6907f3ceccdbad531b1a447c3d45dea",
  );
  assert.equal(
    bytesToHex(initializeChallenge.challenge),
    "113a6db181a1839fc42d97e6be274bb3126ad0ebc23dbf262e0f0a2d6b4381dd",
  );

  const wrapped = buildExecuteInstructions({
    webauthnData: {
      publicKey: Uint8Array.of(0x02, ...new Array(32).fill(0x22)),
      signature: encodeDerSignature(1n, 2n),
      authData: Uint8Array.of(0xaa, 0xbb),
      clientDataJson: new TextEncoder().encode(
        JSON.stringify({
          type: "webauthn.get",
          challenge: "x",
          origin: "https://example.com",
          crossOrigin: false,
        }),
      ),
      clientDataJsonReconstructionParams: {
        typeAndFlags: 0x10,
        port: null,
      },
    },
    passkeyAccount: nonceSigner,
    nonceSigner,
    truncatedSlot: 123,
    recentSlotHash,
    instructions: [],
  });

  assert.equal(
    bytesToHex(Uint8Array.from(wrapped.instruction.data)),
    "0100007b0023022222222222222222222222222222222222222222222222222222222222222222100000",
  );
  assert.equal(
    bytesToHex(wrapped.precompileMessage),
    "aabb02ced0673d034928406f484b7418c8fe648f669d16711882a024ed7e30636372",
  );
  assert.equal(wrapped.challengeBase64Url, "M4BxFOPdlahWFRVYV5lLEfaQfzzszbrVMbGkR8PUXeo");
});

test("decodeSpkiP256PublicKey parses valid SPKI and rejects malformed variants", () => {
  const point = Uint8Array.of(
    0x04,
    ...Array.from({ length: 32 }, (_, i) => i + 1),
    ...Array.from({ length: 31 }, (_, i) => i + 65),
    0x80,
  );
  const validSpki = createP256Spki(point);
  const parsed = decodeSpkiP256PublicKey(validSpki);

  assert.equal(parsed.compressed.length, 33);
  assert.equal(parsed.compressed[0], 0x02);
  assert.deepEqual(parsed.uncompressed, point.slice(1));

  const wrongAlgorithmOid = Uint8Array.from(validSpki);
  wrongAlgorithmOid[10] = 0x02;
  assert.throws(() => decodeSpkiP256PublicKey(wrongAlgorithmOid), ExternalSignatureSdkError);

  const wrongCurveOid = Uint8Array.from(validSpki);
  wrongCurveOid[20] = 0x08;
  assert.throws(() => decodeSpkiP256PublicKey(wrongCurveOid), ExternalSignatureSdkError);

  const malformedBitString = Uint8Array.from(validSpki);
  malformedBitString[22] = 0x02;
  assert.throws(() => decodeSpkiP256PublicKey(malformedBitString), ExternalSignatureSdkError);

  const compressedPoint = createP256Spki(
    Uint8Array.of(0x02, ...Array.from({ length: 32 }, (_, i) => i + 1)),
  );
  assert.throws(() => decodeSpkiP256PublicKey(compressedPoint), ExternalSignatureSdkError);
});

test("numeric guards reject invalid number inputs and preserve valid boundaries", () => {
  assert.throws(() => truncateSlot(1.5), ExternalSignatureSdkError);
  assert.throws(() => truncateSlot(Number.NaN), ExternalSignatureSdkError);
  assert.throws(() => truncateSlot(Number.POSITIVE_INFINITY), ExternalSignatureSdkError);
  assert.equal(truncateSlot(1001), 1);

  assert.throws(() => toLittleEndianU64(1.1), ExternalSignatureSdkError);
  assert.throws(() => toLittleEndianU64(Number.NaN), ExternalSignatureSdkError);
  assert.deepEqual(
    Array.from(toLittleEndianU64(0xffff_ffff_ffff_ffffn)),
    [255, 255, 255, 255, 255, 255, 255, 255],
  );
});

test("parseRegistrationCredential validates browser and authData public keys match", () => {
  const clientDataJSON = new TextEncoder().encode(
    JSON.stringify({
      type: "webauthn.create",
      challenge: "x",
      origin: "https://example.com",
      crossOrigin: false,
    }),
  );
  const x = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const y = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 65));
  const uncompressedPoint = Uint8Array.of(0x04, ...x, ...y);
  const publicKeySpki = createP256Spki(uncompressedPoint);
  const authData = createRegistrationAuthData({ x, y, signCount: 7 });
  const credential = createRegistrationCredential({
    authData,
    signature: Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01),
    clientDataJSON,
    publicKeySpki,
  });

  const parsed = parseRegistrationCredential(credential);
  assert.equal(parsed.publicKey.length, 33);
  assert.equal(parsed.publicKeyUncompressed.length, 64);
  assert.deepEqual(parsed.credentialId, Uint8Array.of(0x01, 0x02, 0x03));
});

test("parseRegistrationCredential falls back to attested credential data when getPublicKey is unavailable", () => {
  const clientDataJSON = new TextEncoder().encode(
    JSON.stringify({
      type: "webauthn.create",
      challenge: "x",
      origin: "https://example.com",
      crossOrigin: false,
    }),
  );
  const x = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const y = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 65));
  const authData = createRegistrationAuthData({ x, y });
  const credential = createRegistrationCredential({
    authData,
    signature: Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01),
    clientDataJSON,
    publicKeySpki: null,
  });

  const parsed = parseRegistrationCredential(credential);
  assert.equal(parsed.publicKey[0], 0x02);
  assert.equal(parsed.publicKey.length, 33);
  assert.equal(parsed.publicKeyUncompressed.length, 64);
});

test("parseRegistrationCredential rejects malformed attestation variants", () => {
  const clientDataJSON = new TextEncoder().encode(
    JSON.stringify({
      type: "webauthn.create",
      challenge: "x",
      origin: "https://example.com",
      crossOrigin: false,
    }),
  );
  const x = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const y = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 65));
  const publicKeySpki = createP256Spki(Uint8Array.of(0x04, ...x, ...y));
  const signature = Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01);

  const missingSig = createRegistrationCredential({
    authData: createRegistrationAuthData({ x, y }),
    signature: null,
    clientDataJSON,
    publicKeySpki,
  });
  assert.throws(() => parseRegistrationCredential(missingSig), ExternalSignatureSdkError);

  const truncatedAuthData = createRegistrationCredential({
    authData: new Uint8Array(20),
    signature,
    clientDataJSON,
    publicKeySpki,
  });
  assert.throws(() => parseRegistrationCredential(truncatedAuthData), ExternalSignatureSdkError);

  const invalidCredentialIdLength = createRegistrationCredential({
    authData: (() => {
      const authData = createRegistrationAuthData({ x, y });
      authData[53] = 0xff;
      authData[54] = 0xff;
      return authData;
    })(),
    signature,
    clientDataJSON,
    publicKeySpki,
  });
  assert.throws(
    () => parseRegistrationCredential(invalidCredentialIdLength),
    ExternalSignatureSdkError,
  );

  const unsupportedAlgorithm = createRegistrationCredential({
    authData: createRegistrationAuthData({ x, y, coseOverrides: { alg: -8 } }),
    signature,
    clientDataJSON,
    publicKeySpki: null,
  });
  assert.throws(() => parseRegistrationCredential(unsupportedAlgorithm), ExternalSignatureSdkError);

  const missingAttestedCredentialData = createRegistrationCredential({
    authData: createRegistrationAuthData({ x, y, flags: 0x01 }),
    signature,
    clientDataJSON,
    publicKeySpki: null,
  });
  assert.throws(
    () => parseRegistrationCredential(missingAttestedCredentialData),
    ExternalSignatureSdkError,
  );
});

test("root entrypoint types compile without DOM libs", () => {
  runTsc({
    lib: "ES2022",
    source: `
      import { truncateSlot, type InitializePasskeyResult } from ${JSON.stringify(DIST_INDEX)};
      const slot = truncateSlot(1001);
      const result = null as InitializePasskeyResult | null;
      console.log(slot, result);
    `,
  });
});

test("browser subpath types compile with DOM libs and expose registration types", () => {
  runTsc({
    lib: "ES2022,DOM",
    source: `
      import {
        parseAuthenticationCredential,
        type RegistrationWebAuthnData,
      } from ${JSON.stringify(DIST_WEBAUTHN)};
      type Parsed = ReturnType<typeof parseAuthenticationCredential>;
      const registration = null as RegistrationWebAuthnData | null;
      const parsed = null as Parsed | null;
      console.log(registration, parsed);
    `,
  });
});

test("npm pack dry run includes root and webauthn entrypoints", () => {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: SDK_DIR,
    encoding: "utf8",
  });
  const [{ files }] = JSON.parse(output);
  const names = files.map((file) => file.path);

  assert.ok(names.includes("dist/index.js"));
  assert.ok(names.includes("dist/index.d.ts"));
  assert.ok(names.includes("dist/webauthn.js"));
  assert.ok(names.includes("dist/webauthn.d.ts"));
});
