import { describe, it, expect } from "vitest";
import { createIdentity } from "../../src/services/identity.js";
import { packEncrypted, unpack } from "../../src/services/didcomm.js";
import { resolveDID } from "../../src/services/did-resolver.js";

describe("createIdentity", () => {
  it("makes a did:peer:4 that resolves to the keys it generated", async () => {
    const identity = createIdentity(["Ed25519", "X25519"]);

    expect(identity.did.startsWith("did:peer:4zQm")).toBe(true);
    expect(identity.shortDid).toBe(identity.did.split(":").slice(0, 3).join(":"));

    const { didDocument } = await resolveDID(identity.did);
    expect(didDocument).toEqual(identity.didDocument);

    expect(identity.didcommDidDoc.authentication).toEqual([
      `${identity.did}#key-1`,
    ]);
    expect(identity.didcommDidDoc.keyAgreement).toEqual([
      `${identity.did}#key-2`,
    ]);
  });

  // didcomm-rust finds a secret by the id of the verification method it belongs
  // to, and a resolved document's ids are absolute.
  it("names the secrets the way the resolved document names the keys", () => {
    const identity = createIdentity(["Ed25519", "X25519"]);

    expect(identity.secrets.map((secret) => secret.id)).toEqual(
      identity.didcommDidDoc.verificationMethod.map((method) => method.id)
    );
    expect(identity.secrets[0].privateKeyJwk).toMatchObject({
      kty: "OKP",
      crv: "Ed25519",
    });
  });

  it("publishes an endpoint only when given one", () => {
    expect(createIdentity(["X25519"]).didcommDidDoc.service).toEqual([]);

    const addressed = createIdentity(["X25519"], "https://example.com/didcomm");
    expect(addressed.didcommDidDoc.service).toEqual([
      {
        id: `${addressed.did}#service`,
        type: "DIDCommMessaging",
        serviceEndpoint: {
          uri: "https://example.com/didcomm",
          accept: ["didcomm/v2"],
          routingKeys: [],
        },
      },
    ]);
  });

  it("generates keys nobody else has", () => {
    expect(createIdentity(["X25519"]).did).not.toBe(
      createIdentity(["X25519"]).did
    );
  });

  // Nothing is pinned and nothing is fetched: two strangers who have only
  // exchanged DIDs can write to each other, because the document is the DID.
  it("can be written to and read from with no documents supplied", async () => {
    const alice = createIdentity(["Ed25519", "X25519"]);
    const bob = createIdentity(["Ed25519", "X25519"], "https://bob.example/in");

    const packed = await packEncrypted({
      message: {
        id: "m-1",
        typ: "application/didcomm-plain+json",
        type: "https://didcomm.org/basicmessage/2.0/message",
        from: alice.did,
        to: [bob.did],
        body: { content: "在嗎" },
      },
      to: bob.did,
      from: alice.did,
      secrets: alice.secrets,
    });

    expect(packed.deliveryEndpoint).toBe("https://bob.example/in");

    const opened = await unpack({
      message: packed.packedMessage,
      secrets: bob.secrets,
    });

    expect(opened.message.body).toEqual({ content: "在嗎" });
    expect(opened.from).toBe(alice.did);
    expect(opened.verifiedFrom).toBe(alice.did);
    expect(opened.senderVerified).toBe(true);
  });
});
