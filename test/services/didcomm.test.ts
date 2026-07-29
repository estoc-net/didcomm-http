import { describe, it, expect } from "vitest";
import {
  packEncrypted,
  packSigned,
  packPlaintext,
  unpack,
} from "../../src/services/didcomm.js";
import { ALICE_DID_DOC, BOB_DID_DOC } from "../fixtures/did-docs.js";
import { ALICE_SECRETS, BOB_SECRETS } from "../fixtures/secrets.js";
import { MESSAGE_SIMPLE, MESSAGE_MINIMAL } from "../fixtures/messages.js";

const allDocs = [ALICE_DID_DOC, BOB_DID_DOC];

describe("DIDComm service", () => {
  describe("packEncrypted + unpack round-trip", () => {
    it("authenticated encryption (alice → bob)", async () => {
      const packed = await packEncrypted({
        message: MESSAGE_SIMPLE,
        to: "did:example:bob",
        from: "did:example:alice",
        didDocs: allDocs,
        secrets: ALICE_SECRETS,
      });

      expect(packed.packedMessage).toBeTypeOf("string");
      expect(packed.metadata.fromKid).toContain("did:example:alice");
      expect(packed.metadata.toKids.length).toBeGreaterThan(0);

      const unpacked = await unpack({
        message: packed.packedMessage,
        didDocs: allDocs,
        secrets: BOB_SECRETS,
      });

      expect(unpacked.message.id).toBe(MESSAGE_SIMPLE.id);
      expect(unpacked.message.body).toEqual(MESSAGE_SIMPLE.body);
      expect(unpacked.metadata.encrypted).toBe(true);
      expect(unpacked.metadata.authenticated).toBe(true);
    });

    it("anonymous encryption (→ bob)", async () => {
      const packed = await packEncrypted({
        message: MESSAGE_SIMPLE,
        to: "did:example:bob",
        from: null,
        didDocs: allDocs,
        secrets: [],
      });

      expect(packed.packedMessage).toBeTypeOf("string");
      expect(packed.metadata.fromKid).toBeFalsy();

      const unpacked = await unpack({
        message: packed.packedMessage,
        didDocs: allDocs,
        secrets: BOB_SECRETS,
      });

      expect(unpacked.message.id).toBe(MESSAGE_SIMPLE.id);
      expect(unpacked.metadata.encrypted).toBe(true);
      expect(unpacked.metadata.anonymousSender).toBe(true);
    });

    it("authenticated encryption with signing (non-repudiation)", async () => {
      const packed = await packEncrypted({
        message: MESSAGE_SIMPLE,
        to: "did:example:bob",
        from: "did:example:alice",
        signBy: "did:example:alice",
        didDocs: allDocs,
        secrets: ALICE_SECRETS,
      });

      expect(packed.metadata.signByKid).toContain("did:example:alice");

      const unpacked = await unpack({
        message: packed.packedMessage,
        didDocs: allDocs,
        secrets: BOB_SECRETS,
      });

      expect(unpacked.metadata.nonRepudiation).toBe(true);
      expect(unpacked.metadata.signedMessage).toBeTypeOf("string");
    });
  });

  describe("packSigned + unpack round-trip", () => {
    it("signed message", async () => {
      const packed = await packSigned({
        message: MESSAGE_SIMPLE,
        signBy: "did:example:alice",
        didDocs: allDocs,
        secrets: ALICE_SECRETS,
      });

      expect(packed.packedMessage).toBeTypeOf("string");
      expect(packed.metadata.signByKid).toContain("did:example:alice");

      const unpacked = await unpack({
        message: packed.packedMessage,
        didDocs: allDocs,
        secrets: [],
      });

      expect(unpacked.message.id).toBe(MESSAGE_SIMPLE.id);
      expect(unpacked.metadata.nonRepudiation).toBe(true);
      expect(unpacked.metadata.encrypted).toBe(false);
    });
  });

  describe("packPlaintext + unpack round-trip", () => {
    it("plaintext message", async () => {
      const packed = await packPlaintext({
        message: MESSAGE_SIMPLE,
        didDocs: allDocs,
      });

      expect(packed.packedMessage).toBeTypeOf("string");

      const parsed = JSON.parse(packed.packedMessage);
      expect(parsed.id).toBe(MESSAGE_SIMPLE.id);
      expect(parsed.type).toBe(MESSAGE_SIMPLE.type);

      const unpacked = await unpack({
        message: packed.packedMessage,
        didDocs: allDocs,
        secrets: [],
      });

      expect(unpacked.message.id).toBe(MESSAGE_SIMPLE.id);
      expect(unpacked.metadata.encrypted).toBe(false);
      expect(unpacked.metadata.nonRepudiation).toBe(false);
    });

    it("minimal message", async () => {
      const packed = await packPlaintext({
        message: MESSAGE_MINIMAL,
        didDocs: allDocs,
      });

      const parsed = JSON.parse(packed.packedMessage);
      expect(parsed.id).toBe(MESSAGE_MINIMAL.id);
    });
  });
});
