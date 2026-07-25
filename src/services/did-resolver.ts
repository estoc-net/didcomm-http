import { Resolver, type DIDDocument } from "did-resolver";
import { getResolver as getWebResolver } from "web-did-resolver";
import { resolveDID as resolveWebVH } from "didwebvh-ts";
import { isPeerDID4, isShortForm, resolveLongForm } from "./did-peer-4.js";

let cachedResolver: Resolver | null = null;

function getDidWebResolver(): Resolver {
  if (!cachedResolver) {
    cachedResolver = new Resolver({ ...getWebResolver() });
  }
  return cachedResolver;
}

export interface ResolveResult {
  // did:peer:4 documents are not DIDDocument-shaped (relative references, no
  // required fields), so the union stays open.
  didDocument: DIDDocument | Record<string, unknown> | null;
  didDocumentMetadata: Record<string, unknown>;
  didResolutionMetadata: {
    contentType?: string;
    error?: string;
    message?: string;
  };
}

export async function resolveDID(did: string): Promise<ResolveResult> {
  if (isPeerDID4(did)) {
    return resolveDidPeer4(did);
  }

  if (did.startsWith("did:webvh:")) {
    return resolveDidWebVH(did);
  }

  if (did.startsWith("did:web:")) {
    return resolveDidWeb(did);
  }

  return {
    didDocument: null,
    didDocumentMetadata: {},
    didResolutionMetadata: {
      error: "methodNotSupported",
      message: `Unsupported DID method: ${did.split(":")[1] ?? "unknown"}`,
    },
  };
}

function resolveDidPeer4(did: string): ResolveResult {
  // The short form carries no document, so it can only be resolved by a party
  // that already holds the long form.
  if (isShortForm(did)) {
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "notFound",
        message:
          "Short form did:peer:4 cannot be resolved on its own; supply the long form, or POST the input document to /did/peer/4/resolve-short",
      },
    };
  }

  try {
    return {
      didDocument: resolveLongForm(did),
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: "application/did+ld+json" },
    };
  } catch (err) {
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "invalidDid",
        message: err instanceof Error ? err.message : String(err),
      },
    };
  }
}

async function resolveDidWeb(did: string): Promise<ResolveResult> {
  const resolver = getDidWebResolver();
  const result = await resolver.resolve(did);
  return {
    didDocument: result.didDocument ?? null,
    didDocumentMetadata: result.didDocumentMetadata ?? {},
    didResolutionMetadata: result.didResolutionMetadata ?? {},
  };
}

async function resolveDidWebVH(did: string): Promise<ResolveResult> {
  try {
    const result = await resolveWebVH(did);
    return {
      didDocument: result.doc ?? null,
      didDocumentMetadata: {
        versionId: result.meta.versionId,
        created: result.meta.created,
        updated: result.meta.updated,
        deactivated: result.meta.deactivated,
        portable: result.meta.portable,
      },
      didResolutionMetadata: {
        contentType: "application/did+ld+json",
        ...(result.meta.error ? { error: String(result.meta.error) } : {}),
      },
    };
  } catch (err) {
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "notFound",
        message: err instanceof Error ? err.message : String(err),
      },
    };
  }
}
