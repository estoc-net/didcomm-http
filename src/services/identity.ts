import { generateKeyPairSync } from "node:crypto";
import bs58 from "bs58";

import type { DIDDoc, Secret } from "../schemas/did.js";
import {
  encodeLongForm,
  longToShort,
  resolveLongForm,
  resolveShortForm,
  type PeerDocument,
} from "./did-peer-4.js";
import { toDIDCommDIDDoc } from "./did-doc.js";

/**
 * A whole did:peer:4 identity made from nothing: fresh keys, the document that
 * names them, the DID that document hashes to, and the secrets to use it.
 *
 * The private halves are handed back to the caller, which is only ever right
 * for an identity that is meant to be temporary — a test, a demo, one side of a
 * conversation nobody will resume. A DID that stands for somebody generates its
 * keys where they will live and never asks for them over a wire.
 */

export const CURVES = ["Ed25519", "X25519"] as const;
export type Curve = (typeof CURVES)[number];

export class KeyGenerationError extends Error {
  readonly name = "KeyGenerationError";
}

const MULTICODEC: Record<Curve, number[]> = {
  Ed25519: [0xed, 0x01],
  X25519: [0xec, 0x01],
};

const VERIFICATION_METHOD_TYPE: Record<Curve, string> = {
  Ed25519: "Ed25519VerificationKey2020",
  X25519: "X25519KeyAgreementKey2020",
};

/** Ed25519 signs and so authenticates; X25519 agrees on keys and so encrypts. */
const RELATIONSHIP: Record<Curve, "authentication" | "keyAgreement"> = {
  Ed25519: "authentication",
  X25519: "keyAgreement",
};

export interface Identity {
  did: string;
  shortDid: string;
  inputDocument: PeerDocument;
  didDocument: PeerDocument;
  shortDidDocument: PeerDocument;
  didcommDidDoc: DIDDoc;
  secrets: Secret[];
}

function keyPair(curve: Curve): { x: string; d: string } {
  // Each curve is its own overload, so the choice cannot be an argument.
  const { privateKey } =
    curve === "Ed25519"
      ? generateKeyPairSync("ed25519")
      : generateKeyPairSync("x25519");
  const jwk = privateKey.export({ format: "jwk" });

  if (typeof jwk.x !== "string" || typeof jwk.d !== "string") {
    throw new KeyGenerationError(`A ${curve} key did not export as a JWK`);
  }

  return { x: jwk.x, d: jwk.d };
}

function multibase(curve: Curve, x: string): string {
  const raw = Buffer.from(x, "base64url");
  return `z${bs58.encode(Buffer.concat([Buffer.from(MULTICODEC[curve]), raw]))}`;
}

function serviceBlock(endpoint: string) {
  return [
    {
      id: "#service",
      type: "DIDCommMessaging",
      serviceEndpoint: {
        uri: endpoint,
        accept: ["didcomm/v2"],
        routingKeys: [],
      },
    },
  ];
}

export function createIdentity(curves: Curve[], endpoint?: string): Identity {
  // No `controller`: an input document is hashed into the DID that controls it,
  // so the controller cannot be named until the naming is done. Resolution
  // fills it in.
  const verificationMethod: Array<{
    id: string;
    type: string;
    publicKeyMultibase: string;
  }> = [];
  const relationships: Record<string, string[]> = {
    authentication: [],
    keyAgreement: [],
  };
  const relativeSecrets: Secret[] = [];

  curves.forEach((curve, index) => {
    const id = `#key-${index + 1}`;
    const { x, d } = keyPair(curve);

    verificationMethod.push({
      id,
      type: VERIFICATION_METHOD_TYPE[curve],
      publicKeyMultibase: multibase(curve, x),
    });

    relationships[RELATIONSHIP[curve]].push(id);

    relativeSecrets.push({
      id,
      type: "JsonWebKey2020",
      privateKeyJwk: { kty: "OKP", crv: curve, x, d },
    });
  });

  const inputDocument: PeerDocument = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    verificationMethod,
    ...(relationships.authentication.length > 0
      ? { authentication: relationships.authentication }
      : {}),
    ...(relationships.keyAgreement.length > 0
      ? { keyAgreement: relationships.keyAgreement }
      : {}),
    ...(endpoint === undefined ? {} : { service: serviceBlock(endpoint) }),
  };

  const did = encodeLongForm(inputDocument);
  const didDocument = resolveLongForm(did);

  return {
    did,
    shortDid: longToShort(did),
    inputDocument,
    didDocument,
    shortDidDocument: resolveShortForm(did),
    didcommDidDoc: toDIDCommDIDDoc(didDocument),
    // didcomm-rust matches a secret to a verification method by id, and the
    // resolved document's ids are absolute, so these have to be too.
    secrets: relativeSecrets.map((secret) => ({
      ...secret,
      id: `${did}${secret.id}`,
    })),
  };
}
