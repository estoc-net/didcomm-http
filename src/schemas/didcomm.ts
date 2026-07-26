import { Type, type Static } from "@sinclair/typebox";
import { DIDDoc, Secret } from "./did.js";

export const Attachment = Type.Object(
  {
    data: Type.Union([
      Type.Object({
        base64: Type.String(),
        jws: Type.Optional(Type.String()),
      }),
      Type.Object({
        json: Type.Unknown(),
        jws: Type.Optional(Type.String()),
      }),
      Type.Object({
        links: Type.Array(Type.String()),
        hash: Type.String(),
        jws: Type.Optional(Type.String()),
      }),
    ]),
    id: Type.Optional(Type.String()),
    description: Type.Optional(Type.String()),
    filename: Type.Optional(Type.String()),
    media_type: Type.Optional(Type.String()),
    format: Type.Optional(Type.String()),
    lastmod_time: Type.Optional(Type.Number()),
    byte_count: Type.Optional(Type.Number()),
  },
  { description: "Message attachment" }
);

export const IMessage = Type.Object(
  {
    id: Type.String({ description: "Unique message ID" }),
    typ: Type.String({
      description: "Message type header",
      default: "application/didcomm-plain+json",
    }),
    type: Type.String({ description: "Message Type URI" }),
    body: Type.Unknown({ description: "Message body" }),
    from: Type.Optional(Type.String({ description: "Sender DID" })),
    to: Type.Optional(
      Type.Array(Type.String(), { description: "Recipient DIDs" })
    ),
    thid: Type.Optional(Type.String({ description: "Thread ID" })),
    pthid: Type.Optional(Type.String({ description: "Parent thread ID" })),
    created_time: Type.Optional(
      Type.Number({ description: "Created time (UTC epoch seconds)" })
    ),
    expires_time: Type.Optional(
      Type.Number({ description: "Expiry time (UTC epoch seconds)" })
    ),
    from_prior: Type.Optional(
      Type.String({ description: "Compact serialized signed JWT" })
    ),
    attachments: Type.Optional(Type.Array(Attachment)),
  },
  {
    description: "DIDComm plaintext message",
    additionalProperties: true,
  }
);
export type IMessage = Static<typeof IMessage>;

/**
 * Documents are resolved, not supplied: did:web, did:webvh, did:peer:2 and
 * did:peer:4 all resolve here, and a mediator standing in front of a recipient
 * resolves along with them. Listing one pins it — used exactly as given, never
 * fetched — which is how a document published nowhere gets in, such as a short
 * form did:peer:4 that only its holder can expand.
 */
const PinnedDIDDocs = Type.Optional(
  Type.Array(DIDDoc, {
    description: "DID Documents to use instead of resolving them",
  })
);

const secretsFor = (whose: string) =>
  Type.Optional(
    Type.Array(Secret, { description: `${whose} secrets (private keys)` })
  );

// --- Pack Encrypted ---

export const PackEncryptedRequest = Type.Object(
  {
    message: IMessage,
    to: Type.String({ description: "Recipient DID or key ID" }),
    from: Type.Optional(
      Type.Union([Type.String(), Type.Null()], {
        description: "Sender DID or key ID (null for anonymous)",
      })
    ),
    sign_by: Type.Optional(
      Type.Union([Type.String(), Type.Null()], {
        description: "Signer DID or key ID for non-repudiation",
      })
    ),
    options: Type.Optional(
      Type.Object({
        protect_sender: Type.Optional(
          Type.Boolean({ description: "Hide sender from mediators" })
        ),
        forward: Type.Optional(
          Type.Boolean({
            description:
              "Wrap in Forward messages for whatever mediators stand in front of the recipient (default: true)",
          })
        ),
        forward_headers: Type.Optional(
          Type.Array(Type.Tuple([Type.String(), Type.String()]))
        ),
        messaging_service: Type.Optional(
          Type.String({ description: "DID URL of messaging service" })
        ),
        enc_alg_auth: Type.Optional(
          Type.Literal("A256cbcHs512Ecdh1puA256kw", {
            description: "Authenticated encryption algorithm",
          })
        ),
        enc_alg_anon: Type.Optional(
          Type.Union(
            [
              Type.Literal("A256cbcHs512EcdhEsA256kw"),
              Type.Literal("Xc20pEcdhEsA256kw"),
              Type.Literal("A256gcmEcdhEsA256kw"),
            ],
            { description: "Anonymous encryption algorithm" }
          )
        ),
      })
    ),
    didDocs: PinnedDIDDocs,
    secrets: secretsFor("Sender"),
  },
  { description: "Pack encrypted request" }
);
export type PackEncryptedRequest = Static<typeof PackEncryptedRequest>;

export const PackEncryptedMetadata = Type.Object({
  messaging_service: Type.Optional(
    Type.Object({
      id: Type.String(),
      service_endpoint: Type.String(),
    })
  ),
  from_kid: Type.Optional(Type.String()),
  sign_by_kid: Type.Optional(Type.String()),
  to_kids: Type.Array(Type.String()),
});

export const PackEncryptedResponse = Type.Object(
  {
    packedMessage: Type.String({ description: "Packed JWE message" }),
    deliveryEndpoint: Type.Union([Type.String(), Type.Null()], {
      description:
        "Where to POST the packed message: a mediator's address when the message was wrapped in a Forward, the recipient's own otherwise, and null when the recipient publishes no DIDComm endpoint at all — which means they can only be answered on a connection they opened",
    }),
    metadata: PackEncryptedMetadata,
  },
  { description: "Pack encrypted response" }
);
export type PackEncryptedResponse = Static<typeof PackEncryptedResponse>;

// --- Pack Signed ---

export const PackSignedRequest = Type.Object(
  {
    message: IMessage,
    sign_by: Type.String({ description: "Signer DID or key ID" }),
    didDocs: PinnedDIDDocs,
    secrets: secretsFor("Signer"),
  },
  { description: "Pack signed request" }
);
export type PackSignedRequest = Static<typeof PackSignedRequest>;

export const PackSignedResponse = Type.Object(
  {
    packedMessage: Type.String({ description: "Packed JWS message" }),
    metadata: Type.Object({
      sign_by_kid: Type.String(),
    }),
  },
  { description: "Pack signed response" }
);
export type PackSignedResponse = Static<typeof PackSignedResponse>;

// --- Pack Plaintext ---

export const PackPlaintextRequest = Type.Object(
  {
    message: IMessage,
    didDocs: PinnedDIDDocs,
  },
  { description: "Pack plaintext request" }
);
export type PackPlaintextRequest = Static<typeof PackPlaintextRequest>;

export const PackPlaintextResponse = Type.Object(
  {
    packedMessage: Type.String({
      description: "Packed plaintext JSON message",
    }),
  },
  { description: "Pack plaintext response" }
);
export type PackPlaintextResponse = Static<typeof PackPlaintextResponse>;

// --- Unpack ---

export const UnpackRequest = Type.Object(
  {
    message: Type.String({ description: "Packed message (JWE/JWS/JSON)" }),
    options: Type.Optional(
      Type.Object({
        expect_decrypt_by_all_keys: Type.Optional(Type.Boolean()),
        unwrap_re_wrapping_forward: Type.Optional(Type.Boolean()),
      })
    ),
    didDocs: PinnedDIDDocs,
    secrets: secretsFor("Recipient"),
  },
  { description: "Unpack request" }
);
export type UnpackRequest = Static<typeof UnpackRequest>;

export const UnpackMetadata = Type.Object({
  encrypted: Type.Boolean(),
  authenticated: Type.Boolean(),
  non_repudiation: Type.Boolean(),
  anonymous_sender: Type.Boolean(),
  re_wrapped_in_forward: Type.Boolean(),
  encrypted_from_kid: Type.Optional(Type.String()),
  encrypted_to_kids: Type.Optional(Type.Array(Type.String())),
  sign_from: Type.Optional(Type.String()),
  from_prior_issuer_kid: Type.Optional(Type.String()),
  enc_alg_auth: Type.Optional(Type.String()),
  enc_alg_anon: Type.Optional(Type.String()),
  sign_alg: Type.Optional(Type.String()),
  signed_message: Type.Optional(Type.String()),
  from_prior: Type.Optional(Type.Unknown()),
});

export const UnpackResponse = Type.Object(
  {
    message: IMessage,
    from: Type.Union([Type.String(), Type.Null()], {
      description:
        "The sender the plaintext claims, which is only a claim: nothing about an envelope binds it to the key that closed it",
    }),
    verifiedFrom: Type.Union([Type.String(), Type.Null()], {
      description:
        "The DID whose key actually closed the envelope, or signed it; null when the message proves nobody, as anonymous encryption does",
    }),
    senderVerified: Type.Boolean({
      description: "Whether the claimed sender is the proven one",
    }),
    encrypted: Type.Boolean(),
    metadata: UnpackMetadata,
  },
  { description: "Unpack response" }
);
export type UnpackResponse = Static<typeof UnpackResponse>;

// --- Error ---

export const ErrorResponse = Type.Object(
  {
    error: Type.String({ description: "Error type" }),
    message: Type.String({ description: "Error message" }),
  },
  { description: "Error response" }
);
export type ErrorResponse = Static<typeof ErrorResponse>;
