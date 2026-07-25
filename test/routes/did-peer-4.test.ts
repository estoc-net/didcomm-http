import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer } from "../../src/server.js";
import {
  PEER_4_INPUT_DOCUMENT,
  PEER_4_SHORT_DID,
} from "../fixtures/peer-did-4.js";
import { generatePeerDID4Party } from "../fixtures/peer-did-4-keys.js";

let app: FastifyInstance;

beforeAll(async () => {
  app = await buildServer();
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

describe("POST /did/peer/4", () => {
  it("derives both forms and a DIDComm-ready DIDDoc", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/did/peer/4",
      payload: { document: PEER_4_INPUT_DOCUMENT },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();

    expect(body.shortDid).toBe(PEER_4_SHORT_DID);
    expect(body.did.startsWith(`${PEER_4_SHORT_DID}:z`)).toBe(true);
    expect(body.didDocument.id).toBe(body.did);
    expect(body.shortDidDocument.id).toBe(body.shortDid);
    expect(body.didcommDidDoc.authentication).toStrictEqual([
      `${body.did}#6MkrCD1c`,
    ]);
  });
});

describe("POST /did/resolve for did:peer:4", () => {
  it("resolves the long form", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/did/peer/4",
      payload: { document: PEER_4_INPUT_DOCUMENT },
    });
    const { did } = created.json();

    const res = await app.inject({
      method: "POST",
      url: "/did/resolve",
      payload: { did },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().didDocument.id).toBe(did);
  });

  it("returns 404 for the short form", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/did/resolve",
      payload: { did: PEER_4_SHORT_DID },
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().didResolutionMetadata.error).toBe("notFound");
  });

  it("returns 400 for a tampered long form", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/did/peer/4",
      payload: { document: PEER_4_INPUT_DOCUMENT },
    });
    const { did } = created.json();

    const res = await app.inject({
      method: "POST",
      url: "/did/resolve",
      payload: { did: `${did}xyz` },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().didResolutionMetadata.error).toBe("invalidDid");
  });
});

describe("POST /did/peer/4/resolve-short", () => {
  it("resolves the short form from its input document", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/did/peer/4/resolve-short",
      payload: { document: PEER_4_INPUT_DOCUMENT, did: PEER_4_SHORT_DID },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().didDocument.id).toBe(PEER_4_SHORT_DID);
  });

  it("rejects a document that does not hash to the supplied DID", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/did/peer/4/resolve-short",
      payload: {
        document: PEER_4_INPUT_DOCUMENT,
        did: "did:peer:4zQmd8CpeFPci817KDsbSAKWcXAE2mjvCQSasRewvbSF54Bc",
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().didResolutionMetadata.error).toBe("invalidDid");
  });
});

describe("POST /did/didcomm-doc", () => {
  it("converts a did:peer:4 into the DIDComm DIDDoc format", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/did/peer/4",
      payload: { document: PEER_4_INPUT_DOCUMENT },
    });
    const { did } = created.json();

    const res = await app.inject({
      method: "POST",
      url: "/did/didcomm-doc",
      payload: { did },
    });

    expect(res.statusCode).toBe(200);
    const { didDoc } = res.json();
    expect(didDoc.id).toBe(did);
    expect(didDoc.keyAgreement).toStrictEqual([`${did}#6LSqPZfn`]);
  });

  it("returns 404 for an unresolvable DID", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/did/didcomm-doc",
      payload: { did: PEER_4_SHORT_DID },
    });

    expect(res.statusCode).toBe(404);
  });
});

describe("POST /did/peer/4 input document validation", () => {
  it("rejects a root id", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/did/peer/4",
      payload: {
        document: { ...PEER_4_INPUT_DOCUMENT, id: "did:example:bogus" },
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("InvalidInputDocument");
  });

  it("rejects an absolute verification method id", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/did/peer/4",
      payload: {
        document: {
          verificationMethod: [
            { id: "did:example:bogus#key-1", type: "Ed25519VerificationKey2020" },
          ],
        },
      },
    });

    expect(res.statusCode).toBe(400);
  });
});

describe("did:peer:4 end to end through DIDComm", () => {
  const create = async (document: Record<string, unknown>) => {
    const res = await app.inject({
      method: "POST",
      url: "/did/peer/4",
      payload: { document },
    });
    expect(res.statusCode).toBe(200);
    return res.json();
  };

  it("packs and unpacks an encrypted message between two peer DIDs", async () => {
    const alice = generatePeerDID4Party("https://alice.example/didcomm");
    const bob = generatePeerDID4Party("https://bob.example/didcomm");

    const aliceDID = await create(alice.inputDocument);
    const bobDID = await create(bob.inputDocument);

    const packed = await app.inject({
      method: "POST",
      url: "/didcomm/pack/encrypted",
      payload: {
        message: {
          id: "peer-4-e2e",
          typ: "application/didcomm-plain+json",
          type: "https://example.com/protocols/test/1.0/message",
          body: { hello: "peer" },
          from: aliceDID.did,
          to: [bobDID.did],
        },
        to: bobDID.did,
        from: aliceDID.did,
        sign_by: aliceDID.did,
        didDocs: [aliceDID.didcommDidDoc, bobDID.didcommDidDoc],
        secrets: alice.secretsFor(aliceDID.did),
      },
    });

    expect(packed.statusCode).toBe(200);
    const { packedMessage } = packed.json();

    const unpacked = await app.inject({
      method: "POST",
      url: "/didcomm/unpack",
      payload: {
        message: packedMessage,
        didDocs: [aliceDID.didcommDidDoc, bobDID.didcommDidDoc],
        secrets: bob.secretsFor(bobDID.did),
      },
    });

    expect(unpacked.statusCode).toBe(200);
    const body = unpacked.json();
    expect(body.message.body).toStrictEqual({ hello: "peer" });
    expect(body.message.from).toBe(aliceDID.did);
    expect(body.metadata.encrypted).toBe(true);
    expect(body.metadata.authenticated).toBe(true);
    expect(body.metadata.non_repudiation).toBe(true);
  });

  it("still packs when a peer's document carries an unsupported key type", async () => {
    const alice = generatePeerDID4Party("https://alice.example/didcomm");
    const bob = generatePeerDID4Party("https://bob.example/didcomm");

    // A counterparty is free to publish key types didcomm-rust cannot read.
    // As long as they are not the keys in use, packing must still succeed.
    const bobDocument = structuredClone(bob.inputDocument);
    bobDocument.verificationMethod.push({
      id: "#key-9",
      type: "UnsupportedVerificationMethod2026",
      publicKeyMultibase: "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7LiK87NzhfWqio5yr",
    });

    const aliceDID = await create(alice.inputDocument);
    const bobDID = await create(bobDocument);

    expect(
      bobDID.didcommDidDoc.verificationMethod.map((method: { type: string }) => method.type)
    ).toContain("Other");

    const packed = await app.inject({
      method: "POST",
      url: "/didcomm/pack/encrypted",
      payload: {
        message: {
          id: "peer-4-unsupported-key",
          typ: "application/didcomm-plain+json",
          type: "https://example.com/protocols/test/1.0/message",
          body: { hello: "peer" },
          from: aliceDID.did,
          to: [bobDID.did],
        },
        to: bobDID.did,
        from: aliceDID.did,
        didDocs: [aliceDID.didcommDidDoc, bobDID.didcommDidDoc],
        secrets: alice.secretsFor(aliceDID.did),
      },
    });

    expect(packed.statusCode).toBe(200);
  });
});
