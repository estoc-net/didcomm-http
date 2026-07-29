import { describe, it, expect } from "vitest";
import { packEncrypted, packSigned, unpack } from "../../src/services/didcomm.js";
import { createIdentity } from "../../src/services/identity.js";

const MEDIATOR_ENDPOINT = "https://mediator.example/message";

function message(to: string, from?: string) {
  return {
    id: "m-1",
    typ: "application/didcomm-plain+json",
    type: "https://didcomm.org/basicmessage/2.0/message",
    ...(from === undefined ? {} : { from }),
    to: [to],
    body: { content: "好" },
  };
}

describe("where a packed message goes", () => {
  it("is the recipient's own address when they have one", async () => {
    const bob = createIdentity(["X25519"], "https://bob.example/in");

    const packed = await packEncrypted({ message: message(bob.did), to: bob.did });

    expect(packed.deliveryEndpoint).toBe("https://bob.example/in");
    // Nobody stands in front of Bob, so nothing was wrapped for anybody.
    expect(packed.metadata.messagingService).toBeFalsy();
  });

  // The case that makes a browser tab or a phone reachable at all: the agent
  // publishes its mediator's DID where an address would go, and the message is
  // wrapped in a forward addressed to the mediator.
  it("is the mediator's address when one stands in front of them", async () => {
    const mediator = createIdentity(["X25519"], MEDIATOR_ENDPOINT);
    const bob = createIdentity(["X25519"], mediator.did);

    const packed = await packEncrypted({ message: message(bob.did), to: bob.did });

    expect(packed.deliveryEndpoint).toBe(MEDIATOR_ENDPOINT);

    const atMediator = await unpack({
      message: packed.packedMessage,
      secrets: mediator.secrets,
    });

    expect(atMediator.message.type).toBe("https://didcomm.org/routing/2.0/forward");
    expect(atMediator.message.body).toMatchObject({ next: bob.did });

    const forwarded = atMediator.message.attachments?.[0]?.data;
    const enclosed = JSON.stringify(
      forwarded !== undefined && "json" in forwarded ? forwarded.json : null
    );

    const atBob = await unpack({ message: enclosed, secrets: bob.secrets });
    expect(atBob.message.body).toEqual({ content: "好" });
  });

  it("is nothing when the recipient publishes no endpoint", async () => {
    const bob = createIdentity(["X25519"]);

    const packed = await packEncrypted({ message: message(bob.did), to: bob.did });

    expect(packed.deliveryEndpoint).toBeNull();
    expect(packed.packedMessage).toBeTypeOf("string");
  });

  it("is nothing when the recipient's endpoint is not for DIDComm v2", async () => {
    const bob = createIdentity(["X25519"], "https://bob.example/in");
    const doc = structuredClone(bob.didcommDidDoc);
    const endpoint = doc.service[0].serviceEndpoint;
    if (typeof endpoint !== "string") {
      endpoint.accept = ["didcomm/aip2;env=rfc19"];
    }

    const packed = await packEncrypted({
      message: message(bob.did),
      to: bob.did,
      didDocs: [doc],
    });

    expect(packed.deliveryEndpoint).toBeNull();
  });
});

describe("who a message is from", () => {
  it("is proven when the claim matches the key that closed the envelope", async () => {
    const alice = createIdentity(["X25519"]);
    const bob = createIdentity(["X25519"]);

    const packed = await packEncrypted({
      message: message(bob.did, alice.did),
      to: bob.did,
      from: alice.did,
      secrets: alice.secrets,
    });

    const opened = await unpack({
      message: packed.packedMessage,
      secrets: bob.secrets,
    });

    expect(opened.from).toBe(alice.did);
    expect(opened.verifiedFrom).toBe(alice.did);
    expect(opened.senderVerified).toBe(true);
  });

  // Unpacking compares nothing: didcomm-rust checks `message.from` against the
  // key only on the way out, and a stranger runs their own packer. So a message
  // can arrive proven to be from one DID and claiming to be from another, and
  // reporting the claim as the sender would let anyone arrive as anyone.
  //
  // Ours is the packer that refuses, which is why the demonstration signs
  // rather than authcrypts — the same two fields, filled from a signature.
  it("is not proven when the claim names somebody else", async () => {
    const alice = createIdentity(["Ed25519"]);

    const packed = await packSigned({
      message: message("did:web:merely.ca", "did:web:merely.ca"),
      signBy: alice.did,
      secrets: alice.secrets,
    });

    const opened = await unpack({ message: packed.packedMessage });

    expect(opened.from).toBe("did:web:merely.ca");
    expect(opened.verifiedFrom).toBe(alice.did);
    expect(opened.senderVerified).toBe(false);
    // Something really was proven here — just not what the message says.
    expect(opened.metadata.nonRepudiation).toBe(true);
  });

  it("is proven by nobody when the envelope was packed anonymously", async () => {
    const bob = createIdentity(["X25519"]);

    const packed = await packEncrypted({
      message: message(bob.did, "did:web:merely.ca"),
      to: bob.did,
    });

    const opened = await unpack({
      message: packed.packedMessage,
      secrets: bob.secrets,
    });

    expect(opened.from).toBe("did:web:merely.ca");
    expect(opened.verifiedFrom).toBeNull();
    expect(opened.senderVerified).toBe(false);
  });
});
