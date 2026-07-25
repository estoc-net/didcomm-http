import { generateKeyPairSync, type KeyObject } from "node:crypto";
import bs58 from "bs58";

import type { Secret } from "../../src/schemas/did.js";

const ED25519_PUB = Uint8Array.from([0xed, 0x01]);
const X25519_PUB = Uint8Array.from([0xec, 0x01]);

function jwk(key: KeyObject): Record<string, unknown> {
  return key.export({ format: "jwk" });
}

function toMultibase(publicKeyJwk: Record<string, unknown>, prefix: Uint8Array) {
  const x = publicKeyJwk.x;
  if (typeof x !== "string") {
    throw new Error("JWK is missing `x`");
  }
  const raw = Buffer.from(x, "base64url");
  return `z${bs58.encode(Buffer.concat([Buffer.from(prefix), raw]))}`;
}

export interface PeerKeyPair {
  publicKeyMultibase: string;
  privateKeyJwk: Record<string, unknown>;
}

function generate(type: "ed25519" | "x25519"): PeerKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync(type);
  return {
    publicKeyMultibase: toMultibase(
      jwk(publicKey),
      type === "ed25519" ? ED25519_PUB : X25519_PUB
    ),
    privateKeyJwk: jwk(privateKey),
  };
}

/**
 * Builds a did:peer:4 input document plus matching secrets, so the DID can be
 * exercised end to end against didcomm-node.
 */
export function generatePeerDID4Party(endpoint: string) {
  const signing = generate("ed25519");
  const keyAgreement = generate("x25519");

  const inputDocument = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    verificationMethod: [
      {
        id: "#key-1",
        type: "Ed25519VerificationKey2020",
        publicKeyMultibase: signing.publicKeyMultibase,
      },
      {
        id: "#key-2",
        type: "X25519KeyAgreementKey2020",
        publicKeyMultibase: keyAgreement.publicKeyMultibase,
      },
    ],
    authentication: ["#key-1"],
    keyAgreement: ["#key-2"],
    service: [
      {
        id: "#didcommmessaging-0",
        type: "DIDCommMessaging",
        serviceEndpoint: {
          uri: endpoint,
          accept: ["didcomm/v2"],
          routingKeys: [],
        },
      },
    ],
  };

  // Secrets are looked up by kid, so their material is independent of how the
  // DID document spells the public key — JWK keeps the fixture simple.
  const secretsFor = (did: string): Secret[] => [
    {
      id: `${did}#key-1`,
      type: "JsonWebKey2020",
      privateKeyJwk: signing.privateKeyJwk,
    },
    {
      id: `${did}#key-2`,
      type: "JsonWebKey2020",
      privateKeyJwk: keyAgreement.privateKeyJwk,
    },
  ];

  return { inputDocument, secretsFor };
}
