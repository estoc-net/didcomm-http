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

export async function packEncrypted(req: PackEncryptedRequest) {
  const didResolver = new ChainedResolver(req.didDocs);
  const secretsResolver = new InMemorySecretsResolver(req.secrets);
  const msg = new Message(req.message);

  const [packedMessage, metadata] = await msg.pack_encrypted(
    req.to,
    req.from ?? null,
    req.sign_by ?? null,
    didResolver,
    secretsResolver,
    {
      // The spec's default, and the only one that reaches an agent behind a
      // mediator. Turning it off packs a message that can be delivered only to
      // a recipient with an address of their own.
      forward: true,
      ...req.options,
    }
  );

  return {
    packedMessage,
    deliveryEndpoint:
      metadata.messaging_service?.service_endpoint ??
      (await deliveryEndpoint(req.to, didResolver)),
    metadata,
  };
}

export async function packSigned(req: PackSignedRequest) {
  const didResolver = new ChainedResolver(req.didDocs);
  const secretsResolver = new InMemorySecretsResolver(req.secrets);
  const msg = new Message(req.message);

  const [packedMessage, metadata] = await msg.pack_signed(
    req.sign_by,
    didResolver,
    secretsResolver
  );

  // WASM types sign_by_kid as String (wrapper), normalize to string primitive
  return {
    packedMessage,
    metadata: { sign_by_kid: String(metadata.sign_by_kid) },
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
    req.options ?? {}
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
    encrypted: metadata.encrypted,
    metadata,
  };
}
