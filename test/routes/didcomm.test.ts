import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildServer } from "../../src/server.js";
import type { FastifyInstance } from "fastify";
import { ALICE_DID_DOC, BOB_DID_DOC } from "../fixtures/did-docs.js";
import { ALICE_SECRETS, BOB_SECRETS } from "../fixtures/secrets.js";
import { MESSAGE_SIMPLE } from "../fixtures/messages.js";

let app: FastifyInstance;

beforeAll(async () => {
  app = await buildServer();
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

describe("POST /didcomm/pack/encrypted", () => {
  it("packs an encrypted message", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/didcomm/pack/encrypted",
      payload: {
        message: MESSAGE_SIMPLE,
        to: "did:example:bob",
        from: "did:example:alice",
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
        secrets: ALICE_SECRETS,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.packedMessage).toBeTypeOf("string");
    expect(body.metadata.to_kids.length).toBeGreaterThan(0);
  });

  it("returns 400 on invalid body", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/didcomm/pack/encrypted",
      payload: { invalid: true },
    });

    expect(res.statusCode).toBe(400);
  });
});

describe("POST /didcomm/pack/signed", () => {
  it("packs a signed message", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/didcomm/pack/signed",
      payload: {
        message: MESSAGE_SIMPLE,
        sign_by: "did:example:alice",
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
        secrets: ALICE_SECRETS,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.packedMessage).toBeTypeOf("string");
    expect(body.metadata.sign_by_kid).toContain("did:example:alice");
  });
});

describe("POST /didcomm/pack/plaintext", () => {
  it("packs a plaintext message", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/didcomm/pack/plaintext",
      payload: {
        message: MESSAGE_SIMPLE,
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.packedMessage).toBeTypeOf("string");
    const parsed = JSON.parse(body.packedMessage);
    expect(parsed.id).toBe(MESSAGE_SIMPLE.id);
  });
});

describe("POST /didcomm/unpack", () => {
  it("unpacks an encrypted message", async () => {
    // First pack
    const packRes = await app.inject({
      method: "POST",
      url: "/didcomm/pack/encrypted",
      payload: {
        message: MESSAGE_SIMPLE,
        to: "did:example:bob",
        from: "did:example:alice",
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
        secrets: ALICE_SECRETS,
      },
    });

    const { packedMessage } = packRes.json();

    // Then unpack
    const unpackRes = await app.inject({
      method: "POST",
      url: "/didcomm/unpack",
      payload: {
        message: packedMessage,
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
        secrets: BOB_SECRETS,
      },
    });

    expect(unpackRes.statusCode).toBe(200);
    const body = unpackRes.json();
    expect(body.message.id).toBe(MESSAGE_SIMPLE.id);
    expect(body.metadata.encrypted).toBe(true);
    expect(body.metadata.authenticated).toBe(true);
  });

  it("unpacks a plaintext message", async () => {
    const packRes = await app.inject({
      method: "POST",
      url: "/didcomm/pack/plaintext",
      payload: {
        message: MESSAGE_SIMPLE,
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
      },
    });

    const { packedMessage } = packRes.json();

    const unpackRes = await app.inject({
      method: "POST",
      url: "/didcomm/unpack",
      payload: {
        message: packedMessage,
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
        secrets: [],
      },
    });

    expect(unpackRes.statusCode).toBe(200);
    const body = unpackRes.json();
    expect(body.message.id).toBe(MESSAGE_SIMPLE.id);
    expect(body.metadata.encrypted).toBe(false);
  });
});

// These have to be asserted on a serialized response rather than on what the
// service returns, because serializing is where they went wrong: the WASM says
// `null` for an optional it did not set, and fast-json-stringify wrote that out
// as the empty value of whatever the schema calls the field. A caller strict
// enough to read the schema — a generated client — then met a signing key whose
// id was "" and a messaging service with neither an id nor an address.
describe("the fields a response leaves out", () => {
  async function packed(payload: object) {
    const res = await app.inject({
      method: "POST",
      url: "/didcomm/pack/encrypted",
      payload: {
        message: MESSAGE_SIMPLE,
        to: "did:example:bob",
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
        ...payload,
      },
    });

    expect(res.statusCode).toBe(200);
    return res.json();
  }

  it("says nothing about a signature that was never asked for", async () => {
    const { metadata } = await packed({
      from: "did:example:alice",
      secrets: ALICE_SECRETS,
    });

    expect(metadata).not.toHaveProperty("sign_by_kid");
    expect(metadata.from_kid).toContain("did:example:alice");
  });

  it("says nothing about a forward nobody wrapped", async () => {
    const { metadata } = await packed({});

    // Anonymous, so there is no sender key either.
    expect(metadata).not.toHaveProperty("messaging_service");
    expect(metadata).not.toHaveProperty("from_kid");
    expect(metadata.to_kids.length).toBeGreaterThan(0);
  });

  it("says nothing about the headers an envelope did not carry", async () => {
    const { packedMessage } = await packed({
      from: "did:example:alice",
      secrets: ALICE_SECRETS,
    });

    const res = await app.inject({
      method: "POST",
      url: "/didcomm/unpack",
      payload: {
        message: packedMessage,
        didDocs: [ALICE_DID_DOC, BOB_DID_DOC],
        secrets: BOB_SECRETS,
      },
    });

    const { metadata } = res.json();

    // Encrypted but not signed, so everything a signature would have said is
    // unsaid — including `sign_from`, which is half of what proves a sender.
    expect(metadata).not.toHaveProperty("sign_from");
    expect(metadata).not.toHaveProperty("sign_alg");
    expect(metadata).not.toHaveProperty("signed_message");
    expect(metadata).not.toHaveProperty("from_prior");
    expect(metadata).not.toHaveProperty("from_prior_issuer_kid");

    // Authcrypt, so the anonymous algorithm is unsaid and the authenticated
    // one is not: absent has to mean absent, not "every optional is dropped".
    expect(metadata).not.toHaveProperty("enc_alg_anon");
    expect(metadata.enc_alg_auth).toBeTypeOf("string");
    expect(metadata.non_repudiation).toBe(false);
  });
});
