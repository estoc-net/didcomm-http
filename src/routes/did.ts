import type { FastifyReply } from "fastify";
import type { TypedFastify } from "../types/fastify.js";
import {
  DIDCommDIDDocResponse,
  DIDParams,
  DIDResolutionResult,
  DIDResolveRequest,
  PeerDID4EncodeRequest,
  PeerDID4EncodeResponse,
  PeerDID4GenerateRequest,
  PeerDID4GenerateResponse,
  PeerDID4ResolveShortRequest,
} from "../schemas/did.js";
import { ErrorResponse } from "../schemas/didcomm.js";

import { resolveDID } from "../services/did-resolver.js";
import { toDIDCommDIDDoc } from "@estoc/did-peer";
import { CURVES, createIdentity } from "../services/identity.js";
import {
  encodeLongForm,
  longToShort,
  resolveLongForm,
  resolveShortForm,
  resolveShortFormFromDocument,
  validateInputDocument,
} from "@estoc/did-peer";

const RESOLUTION_ERROR_STATUS: Record<string, 400> = {
  methodNotSupported: 400,
  invalidDid: 400,
};

export async function didRoutes(fastify: TypedFastify) {
  const didPathPrefix = `${fastify.prefix}/did/`;

  /**
   * The DID as the request wire carried it, not as the router decoded it.
   *
   * A DID is already a valid path segment, and any %XX in it is part of the
   * DID: did:web:example.com%3A8080 names a port precisely because the %3A is
   * not a colon. The router's params arrive decoded, which would collapse that
   * DID into a different one, so the path segment is taken verbatim instead.
   */
  const didInPath = (rawUrl: string | undefined, suffix: string): string => {
    const path = (rawUrl ?? "").split("?")[0];
    const segment = path.slice(didPathPrefix.length);
    return suffix !== "" && segment.endsWith(suffix)
      ? segment.slice(0, -suffix.length)
      : segment;
  };

  const resolved = async (did: string, reply: FastifyReply) => {
    const result = await resolveDID(did);

    const error = result.didResolutionMetadata.error;
    if (error) {
      reply.status(RESOLUTION_ERROR_STATUS[error] ?? 404);
    }

    return result;
  };

  fastify.get("/did/:did", {
    schema: {
      tags: ["DID"],
      summary: "Resolve a DID (did:web + did:webvh + did:peer:2 + did:peer:4)",
      description:
        "The DID goes in the path as it is — its own percent-escapes and all. Errors come back as a DID Resolution Result too, with the reason in didResolutionMetadata.error.",
      params: DIDParams,
      response: {
        200: DIDResolutionResult,
        400: DIDResolutionResult,
        404: DIDResolutionResult,
      },
    },
    handler: async (request, reply) => {
      return resolved(didInPath(request.raw.url, ""), reply);
    },
  });

  fastify.post("/did/resolve", {
    schema: {
      tags: ["DID"],
      summary: "Resolve a DID passed in the body",
      description:
        "GET /did/{did} for the DIDs a URL cannot comfortably hold, such as a long form did:peer:4.",
      body: DIDResolveRequest,
      response: {
        200: DIDResolutionResult,
        400: DIDResolutionResult,
        404: DIDResolutionResult,
      },
    },
    handler: async (request, reply) => {
      return resolved(request.body.did, reply);
    },
  });

  fastify.get("/did/:did/didcomm", {
    schema: {
      tags: ["DID"],
      summary: "Resolve a DID into the DIDComm DIDDoc format",
      description:
        "Resolves a DID and converts the document into the flat shape the /didcomm/* endpoints accept: absolute DID URLs, embedded verification methods hoisted, non-DIDCommMessaging services dropped. A DID that does not resolve answers exactly as GET /did/{did} does.",
      params: DIDParams,
      response: {
        200: DIDCommDIDDocResponse,
        400: DIDResolutionResult,
        404: DIDResolutionResult,
      },
    },
    handler: async (request, reply) => {
      const did = didInPath(request.raw.url, "/didcomm");
      const result = await resolveDID(did);

      const error = result.didResolutionMetadata.error;
      if (error || result.didDocument === null) {
        reply.status(RESOLUTION_ERROR_STATUS[error ?? ""] ?? 404);
        return result;
      }

      return { didDoc: toDIDCommDIDDoc(result.didDocument) };
    },
  });

  fastify.post("/did/peer/4/encode", {
    schema: {
      tags: ["DID"],
      summary: "Derive a did:peer:4 from an input document",
      description:
        "Derives the long and short form did:peer:4 for an input document and returns both resolved documents, plus a DIDComm-ready DIDDoc for the long form. The keys already exist and stay wherever they live — only the document travels.",
      body: PeerDID4EncodeRequest,
      response: {
        200: PeerDID4EncodeResponse,
        400: ErrorResponse,
      },
    },
    handler: async (request, reply) => {
      try {
        validateInputDocument(request.body.document);
      } catch (err) {
        return reply.status(400).send({
          error: "InvalidInputDocument",
          message: err instanceof Error ? err.message : String(err),
        });
      }

      const did = encodeLongForm(request.body.document);
      const didDocument = resolveLongForm(did);

      return {
        did,
        shortDid: longToShort(did),
        didDocument,
        shortDidDocument: resolveShortForm(did),
        didcommDidDoc: toDIDCommDIDDoc(didDocument),
      };
    },
  });

  fastify.post("/did/peer/4/generate", {
    schema: {
      tags: ["DID"],
      summary: "Generate keys and the did:peer:4 that names them",
      description:
        "Everything /did/peer/4/encode needs, made here: fresh keys, the input document, the DID, and the secrets to use it. The private keys are in the response, so this suits an identity meant to be temporary — a test, a demo, one side of a conversation nobody will resume. A DID that stands for somebody generates its keys where they will live.",
      body: PeerDID4GenerateRequest,
      response: {
        200: PeerDID4GenerateResponse,
        400: ErrorResponse,
      },
    },
    handler: async (request) => {
      const { keys, service } = request.body;

      return createIdentity(keys ?? [...CURVES], service);
    },
  });

  fastify.post("/did/peer/4/resolve-short", {
    schema: {
      tags: ["DID"],
      summary: "Resolve a short form did:peer:4 from its input document",
      description:
        "A short form did:peer:4 carries no document, so the caller must supply the input document it was derived from.",
      body: PeerDID4ResolveShortRequest,
      response: {
        200: DIDResolutionResult,
        400: DIDResolutionResult,
      },
    },
    handler: async (request, reply) => {
      const { document, did } = request.body;

      try {
        return {
          didDocument: resolveShortFormFromDocument(document, did),
          didDocumentMetadata: {},
          didResolutionMetadata: { contentType: "application/did+ld+json" },
        };
      } catch (err) {
        reply.status(400);
        return {
          didDocument: null,
          didDocumentMetadata: {},
          didResolutionMetadata: {
            error: "invalidDid",
            message: err instanceof Error ? err.message : String(err),
          },
        };
      }
    },
  });
}
