import { Type } from "@sinclair/typebox";
import type { FastifyInstance } from "fastify";
import type { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import {
  DIDCommDIDDocRequest,
  DIDCommDIDDocResponse,
  DIDResolutionResult,
  PeerDID4CreateRequest,
  PeerDID4CreateResponse,
  PeerDID4ResolveShortRequest,
} from "../schemas/did.js";
import { ErrorResponse } from "../schemas/didcomm.js";

import { resolveDID } from "../services/did-resolver.js";
import { toDIDCommDIDDoc } from "../services/did-doc.js";
import {
  encodeLongForm,
  longToShort,
  resolveLongForm,
  resolveShortForm,
  resolveShortFormFromDocument,
  validateInputDocument,
} from "../services/did-peer-4.js";

type TypedFastify = FastifyInstance<any, any, any, any, TypeBoxTypeProvider>;

const RESOLUTION_ERROR_STATUS: Record<string, 400> = {
  methodNotSupported: 400,
  invalidDid: 400,
};

export async function didRoutes(fastify: TypedFastify) {
  fastify.post("/did/resolve", {
    schema: {
      tags: ["DID"],
      summary: "Resolve a DID (did:web + did:webvh + did:peer:4)",
      body: Type.Object({
        did: Type.String({
          description: "DID to resolve, e.g. did:web:example.com",
        }),
      }),
      response: {
        200: DIDResolutionResult,
        400: DIDResolutionResult,
        404: DIDResolutionResult,
      },
    },
    handler: async (request, reply) => {
      const { did } = request.body;

      const result = await resolveDID(did);

      const error = result.didResolutionMetadata.error;
      if (error) {
        reply.status(RESOLUTION_ERROR_STATUS[error] ?? 404);
      }

      return result;
    },
  });

  fastify.post("/did/didcomm-doc", {
    schema: {
      tags: ["DID"],
      summary: "Resolve a DID into the DIDComm DIDDoc format",
      description:
        "Resolves a DID and converts the document into the flat shape the /didcomm/* endpoints accept: absolute DID URLs, embedded verification methods hoisted, non-DIDCommMessaging services dropped.",
      body: DIDCommDIDDocRequest,
      response: {
        200: DIDCommDIDDocResponse,
        400: ErrorResponse,
        404: ErrorResponse,
      },
    },
    handler: async (request, reply) => {
      const { did } = request.body;

      const result = await resolveDID(did);
      const error = result.didResolutionMetadata.error;

      if (error || result.didDocument === null) {
        return reply.status(RESOLUTION_ERROR_STATUS[error ?? ""] ?? 404).send({
          error: error ?? "notFound",
          message: result.didResolutionMetadata.message ?? `Could not resolve ${did}`,
        });
      }

      return { didDoc: toDIDCommDIDDoc(result.didDocument) };
    },
  });

  fastify.post("/did/peer/4", {
    schema: {
      tags: ["DID"],
      summary: "Create a did:peer:4 from an input document",
      description:
        "Derives the long and short form did:peer:4 for an input document and returns both resolved documents, plus a DIDComm-ready DIDDoc for the long form.",
      body: PeerDID4CreateRequest,
      response: {
        200: PeerDID4CreateResponse,
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
