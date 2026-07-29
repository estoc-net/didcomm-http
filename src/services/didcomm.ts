import { Message } from "didcomm-node";
import type { DIDDoc, DIDResolver, Secret, SecretsResolver } from "didcomm-node";
import type {
  PackEncryptedRequest,
  PackSignedRequest,
  PackPlaintextRequest,
  UnpackRequest,
} from "../schemas/didcomm.js";
import { resolveDIDCommDoc } from "./did-resolver.js";

const DIDCOMM_V2_PROFILE = "didcomm/v2";

/**
 * The documents the caller pinned, and then the world.
 *
 * Pinning answers the two questions resolution cannot: a document that is
 * published nowhere — a short form did:peer:4 whose long form only the caller
 * holds — and a document the caller wants used exactly as given, whatever is
 * currently on the network.
 */
export class ChainedResolver implements DIDResolver {
  private pinned: Map<string, DIDDoc>;

  constructor(didDocs: DIDDoc[] = []) {
    this.pinned = new Map(didDocs.map((doc) => [doc.id, doc]));
  }

  async resolve(did: string): Promise<DIDDoc | null> {
    return this.pinned.get(did) ?? (await resolveDIDCommDoc(did));
  }
}

export class InMemorySecretsResolver implements SecretsResolver {
  private secrets: Map<string, Secret>;

  constructor(secrets: Secret[] = []) {
    this.secrets = new Map(secrets.map((s) => [s.id, s]));
  }

  async get_secret(secretId: string): Promise<Secret | null> {
    return this.secrets.get(secretId) ?? null;
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    return secretIds.filter((id) => this.secrets.has(id));
  }
}

/** A key ID names a DID and a key within it; everything here wants the DID. */
function didOf(value: string | null | undefined): string | null {
  return value ? value.split("#")[0] : null;
}

/**
 * The optional fields the WASM actually filled in.
 *
 * didcomm-rust returns `null` for every optional it did not set, though its own
 * types call those fields absent. A `null` then reaches fast-json-stringify,
 * which serializes it as the empty value of whatever the schema says the field
 * is: an unsigned message left here carrying `sign_by_kid: ""`, and one nobody
 * forwarded carried `messaging_service: {}`. Both read as a fact — a key with
 * no id, a service with no address — where the truth is that nothing was said.
 * Dropping the nulls makes the value match the type it already claims.
 */
function stated<T extends object>(value: T): Partial<T> {
  const kept: Partial<T> = {};

  for (const key in value) {
    if (value[key] !== null) {
      kept[key] = value[key];
    }
  }

  return kept;
}

function endpointURI(service: DIDDoc["service"][number]): string | null {
  const { serviceEndpoint } = service;

  if (typeof serviceEndpoint === "string") {
    return serviceEndpoint;
  }

  return typeof serviceEndpoint?.uri === "string" ? serviceEndpoint.uri : null;
}

/**
 * The first DIDCommMessaging service that will take a v2 message — the same one
 * the packer picks, so that the address reported here is the address the
 * message was packed for.
 */
function messagingService(doc: DIDDoc): DIDDoc["service"][number] | null {
  return (
    doc.service?.find((service) => {
      if (service.type !== "DIDCommMessaging") {
        return false;
      }

      const accept =
        typeof service.serviceEndpoint === "string"
          ? undefined
          : service.serviceEndpoint?.accept;

      return (
        accept === undefined ||
        accept === null ||
        accept.length === 0 ||
        accept.includes(DIDCOMM_V2_PROFILE)
      );
    }) ?? null
  );
}

/**
 * Where a message packed for `to` should be posted.
 *
 * The packer answers this itself whenever it wrapped a forward, since a forward
 * is addressed to a mediator rather than to the recipient, and only the packer
 * walked the chain to find it. It says nothing when it wrapped none, so a
 * recipient reachable directly is looked up here — by then their service is
 * known to hold a URL, because a DID there would have been a mediator and would
 * have produced a forward.
 */
async function deliveryEndpoint(
  to: string,
  resolver: DIDResolver
): Promise<string | null> {
  const did = didOf(to);
  if (did === null) {
    return null;
  }

  const doc = await resolver.resolve(did);
  if (doc === null) {
    return null;
  }

  const service = messagingService(doc);
  if (service === null) {
    return null;
  }

  const uri = endpointURI(service);
  return uri !== null && !uri.startsWith("did:") ? uri : null;
}

/**
 * The API speaks camelCase for everything that is its own; didcomm-rust speaks
 * snake_case. The seam is here, so neither side leaks into the other. Spreading
 * a `false` spreads nothing, which keeps an option the caller left unsaid
 * unsaid at the WASM boundary too.
 */
function wasmPackOptions(options: PackEncryptedRequest["options"]) {
  return {
    // The spec's default, and the only one that reaches an agent behind a
    // mediator. Turning it off packs a message that can be delivered only to
    // a recipient with an address of their own.
    forward: options?.forward ?? true,
    ...(options?.protectSender !== undefined && {
      protect_sender: options.protectSender,
    }),
    ...(options?.forwardHeaders !== undefined && {
      forward_headers: options.forwardHeaders,
    }),
    ...(options?.messagingService !== undefined && {
      messaging_service: options.messagingService,
    }),
    ...(options?.encAlgAnon !== undefined && {
      enc_alg_anon: options.encAlgAnon,
    }),
  };
}

export async function packEncrypted(req: PackEncryptedRequest) {
  const didResolver = new ChainedResolver(req.didDocs);
  const secretsResolver = new InMemorySecretsResolver(req.secrets);
  const msg = new Message(req.message);

  const [packedMessage, metadata] = await msg.pack_encrypted(
    req.to,
    req.from ?? null,
    req.signBy ?? null,
    didResolver,
    secretsResolver,
    wasmPackOptions(req.options)
  );

  const service = metadata.messaging_service;

  return {
    packedMessage,
    deliveryEndpoint:
      service?.service_endpoint ??
      (await deliveryEndpoint(req.to, didResolver)),
    // The recipients are always known; everything else was said or it was not.
    metadata: {
      ...stated({
        fromKid: metadata.from_kid,
        signByKid: metadata.sign_by_kid,
      }),
      ...(service !== undefined &&
        service !== null && {
          messagingService: {
            id: service.id,
            serviceEndpoint: service.service_endpoint,
          },
        }),
      toKids: metadata.to_kids,
    },
  };
}

export async function packSigned(req: PackSignedRequest) {
  const didResolver = new ChainedResolver(req.didDocs);
  const secretsResolver = new InMemorySecretsResolver(req.secrets);
  const msg = new Message(req.message);

  const [packedMessage, metadata] = await msg.pack_signed(
    req.signBy,
    didResolver,
    secretsResolver
  );

  // WASM types sign_by_kid as String (wrapper), normalize to string primitive
  return {
    packedMessage,
    metadata: { signByKid: String(metadata.sign_by_kid) },
  };
}

export async function packPlaintext(req: PackPlaintextRequest) {
  const didResolver = new ChainedResolver(req.didDocs);
  const msg = new Message(req.message);

  const packedMessage = await msg.pack_plaintext(didResolver);

  return { packedMessage };
}

export async function unpack(req: UnpackRequest) {
  const didResolver = new ChainedResolver(req.didDocs);
  const secretsResolver = new InMemorySecretsResolver(req.secrets);

  const [msg, metadata] = await Message.unpack(
    req.message,
    didResolver,
    secretsResolver,
    {
      ...(req.options?.expectDecryptByAllKeys !== undefined && {
        expect_decrypt_by_all_keys: req.options.expectDecryptByAllKeys,
      }),
      ...(req.options?.unwrapReWrappingForward !== undefined && {
        unwrap_re_wrapping_forward: req.options.unwrapReWrappingForward,
      }),
    }
  );

  const message = msg.as_value();

  // Opening an envelope proves who held the key that closed it. It does not
  // prove the `from` in the plaintext, which didcomm-rust never compares against
  // that key — anyone can authcrypt with their own and write somebody else's DID
  // in the header. So the claim and the proof are reported apart, and only their
  // agreement is a verified sender.
  const from = message.from ?? null;
  const verifiedFrom = didOf(metadata.encrypted_from_kid ?? metadata.sign_from);

  return {
    message,
    from,
    verifiedFrom,
    senderVerified: verifiedFrom !== null && verifiedFrom === from,
    // What an envelope was is always answered; what was in its headers is not.
    metadata: {
      ...stated({
        encryptedFromKid: metadata.encrypted_from_kid,
        encryptedToKids: metadata.encrypted_to_kids,
        signFrom: metadata.sign_from,
        fromPriorIssuerKid: metadata.from_prior_issuer_kid,
        encAlgAuth: metadata.enc_alg_auth,
        encAlgAnon: metadata.enc_alg_anon,
        signAlg: metadata.sign_alg,
        signedMessage: metadata.signed_message,
        fromPrior: metadata.from_prior,
      }),
      encrypted: metadata.encrypted,
      authenticated: metadata.authenticated,
      nonRepudiation: metadata.non_repudiation,
      anonymousSender: metadata.anonymous_sender,
      reWrappedInForward: metadata.re_wrapped_in_forward,
    },
  };
}
