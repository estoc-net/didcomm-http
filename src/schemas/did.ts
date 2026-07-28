import { Type, type Static } from "@sinclair/typebox";
import { shared } from "./shared.js";

export const VerificationMethodType = Type.String({
  description:
    'Verification method type, e.g. "JsonWebKey2020", "X25519KeyAgreementKey2019"',
  examples: ["JsonWebKey2020"],
});

export const VerificationMethod = shared(
  "VerificationMethod",
  Type.Object(
    {
      id: Type.String({ description: "Verification method ID (DID URL)" }),
      type: VerificationMethodType,
      controller: Type.String({ description: "Controller DID" }),
      publicKeyJwk: Type.Optional(
        Type.Record(Type.String(), Type.Unknown(), {
          description: "Public key in JWK format",
        })
      ),
      publicKeyMultibase: Type.Optional(
        Type.String({ description: "Public key in multibase format" })
      ),
      publicKeyBase58: Type.Optional(
        Type.String({ description: "Public key in base58 format" })
      ),
    },
    { description: "DID Document Verification Method" }
  )
);
export type VerificationMethod = Static<typeof VerificationMethod>;

// Left inline rather than named, because it is one branch of a union with no
// discriminator: a client cannot tell which branch it is holding, so the name
// would appear in the document and be reachable from nothing.
export const ServiceEndpoint = Type.Object(
  {
    uri: Type.String(),
    accept: Type.Optional(Type.Array(Type.String())),
    routingKeys: Type.Optional(Type.Array(Type.String())),
  },
  { description: "Service endpoint" }
);

export const Service = shared(
  "Service",
  Type.Object(
    {
      id: Type.String(),
      type: Type.String(),
      serviceEndpoint: Type.Union([ServiceEndpoint, Type.String()]),
    },
    { description: "DID Document Service" }
  )
);
export type Service = Static<typeof Service>;

export const DIDDoc = shared(
  "DIDDoc",
  Type.Object(
    {
      id: Type.String({ description: "DID for the document" }),
      keyAgreement: Type.Array(Type.String(), {
        description: "DID URLs for key agreement verification methods",
      }),
      authentication: Type.Array(Type.String(), {
        description: "DID URLs for authentication verification methods",
      }),
      verificationMethod: Type.Array(VerificationMethod, {
        description: "Verification methods",
      }),
      service: Type.Array(Service, { description: "Services" }),
    },
    { description: "DID Document in DIDComm WASM format" }
  )
);
export type DIDDoc = Static<typeof DIDDoc>;

export const Secret = shared(
  "Secret",
  Type.Object(
    {
      id: Type.String({ description: "Key ID (DID URL)" }),
      type: Type.String({
        description: "Secret type, must match verification method type",
        examples: ["JsonWebKey2020"],
      }),
      privateKeyJwk: Type.Optional(
        Type.Record(Type.String(), Type.Unknown(), {
          description: "Private key in JWK format",
        })
      ),
      privateKeyMultibase: Type.Optional(
        Type.String({ description: "Private key in multibase format" })
      ),
      privateKeyBase58: Type.Optional(
        Type.String({ description: "Private key in base58 format" })
      ),
    },
    { description: "Secret (private key)" }
  )
);
export type Secret = Static<typeof Secret>;

const PeerDID4InputDocument = Type.Record(Type.String(), Type.Unknown(), {
  description:
    "did:peer:4 input document — a DID document without `id`, using relative references such as `#key-1`",
  examples: [
    {
      "@context": ["https://www.w3.org/ns/did/v1"],
      verificationMethod: [
        {
          id: "#key-1",
          type: "Ed25519VerificationKey2020",
          publicKeyMultibase: "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7LiK87NzhfWqio5yr",
        },
      ],
      authentication: ["#key-1"],
    },
  ],
});

export const PeerDID4CreateRequest = Type.Object(
  { document: PeerDID4InputDocument },
  { description: "Derive a did:peer:4 from an input document" }
);
export type PeerDID4CreateRequest = Static<typeof PeerDID4CreateRequest>;

export const PeerDID4CreateResponse = Type.Object(
  {
    did: Type.String({ description: "Long form did:peer:4 (self-certifying)" }),
    shortDid: Type.String({ description: "Short form did:peer:4" }),
    didDocument: Type.Any({
      description: "Resolved document for the long form DID",
    }),
    shortDidDocument: Type.Any({
      description: "Resolved document for the short form DID",
    }),
    didcommDidDoc: DIDDoc,
  },
  { description: "Derived did:peer:4 identifiers and documents" }
);
export type PeerDID4CreateResponse = Static<typeof PeerDID4CreateResponse>;

export const PeerDID4GenerateRequest = Type.Object(
  {
    keys: Type.Optional(
      Type.Array(
        Type.Union([Type.Literal("Ed25519"), Type.Literal("X25519")]),
        {
          description:
            "Curves to generate, in order, named #key-1 onwards. Ed25519 lands in `authentication`, X25519 in `keyAgreement`; an agent that both proves who it is and receives encrypted messages needs one of each, which is the default.",
          default: ["Ed25519", "X25519"],
        }
      )
    ),
    service: Type.Optional(
      Type.String({
        description:
          "DIDCommMessaging endpoint to publish: a URL to be posted to, or a mediator's DID to be reached through. Left out, the identity has no address, and can only be answered on a connection it opened.",
        examples: ["https://example.com/didcomm"],
      })
    ),
  },
  {
    description:
      "Generate keys and the did:peer:4 that names them. The private keys come back in the response, so this is for identities meant to be temporary.",
  }
);
export type PeerDID4GenerateRequest = Static<typeof PeerDID4GenerateRequest>;

export const PeerDID4GenerateResponse = Type.Object(
  {
    did: Type.String({ description: "Long form did:peer:4 (self-certifying)" }),
    shortDid: Type.String({ description: "Short form did:peer:4" }),
    inputDocument: PeerDID4InputDocument,
    didDocument: Type.Any({
      description: "Resolved document for the long form DID",
    }),
    shortDidDocument: Type.Any({
      description: "Resolved document for the short form DID",
    }),
    didcommDidDoc: DIDDoc,
    secrets: Type.Array(Secret, {
      description:
        "The private keys, ready to hand to the /didcomm/* endpoints",
    }),
  },
  { description: "A generated did:peer:4 identity" }
);
export type PeerDID4GenerateResponse = Static<typeof PeerDID4GenerateResponse>;

export const PeerDID4ResolveShortRequest = Type.Object(
  {
    document: PeerDID4InputDocument,
    did: Type.Optional(
      Type.String({
        description:
          "Expected short form DID; when supplied, the document is verified to hash to it",
      })
    ),
  },
  { description: "Resolve a short form did:peer:4 from its input document" }
);
export type PeerDID4ResolveShortRequest = Static<
  typeof PeerDID4ResolveShortRequest
>;

export const DIDCommDIDDocRequest = Type.Object(
  {
    did: Type.String({
      description: "DID to resolve and convert to the DIDComm DIDDoc format",
    }),
  },
  { description: "Resolve a DID into the DIDComm WASM DIDDoc format" }
);
export type DIDCommDIDDocRequest = Static<typeof DIDCommDIDDocRequest>;

export const DIDCommDIDDocResponse = Type.Object(
  { didDoc: DIDDoc },
  {
    description:
      "DID document in the format accepted by the /didcomm/* endpoints",
  }
);
export type DIDCommDIDDocResponse = Static<typeof DIDCommDIDDocResponse>;

// Named, and so one type across the five responses that return it: /did/resolve
// answers with this on 200, 400 and 404, and a caller that rescued the error
// used to be handed a type whose name said the call had succeeded.
export const DIDResolutionResult = shared(
  "DIDResolutionResult",
  Type.Object(
    {
      didDocument: Type.Any({ description: "Resolved DID Document" }),
      didDocumentMetadata: Type.Record(Type.String(), Type.Unknown(), {
        description: "DID Document metadata",
      }),
      didResolutionMetadata: Type.Object({
        contentType: Type.Optional(Type.String()),
        error: Type.Optional(Type.String()),
        message: Type.Optional(Type.String()),
      }),
    },
    { description: "DID Resolution Result (W3C format)" }
  )
);
export type DIDResolutionResult = Static<typeof DIDResolutionResult>;
