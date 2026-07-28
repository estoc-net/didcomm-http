import type { TypedFastify } from "../types/fastify.js";
import {
  PackEncryptedRequest,
  PackEncryptedResponse,
  PackSignedRequest,
  PackSignedResponse,
  PackPlaintextRequest,
  PackPlaintextResponse,
  UnpackRequest,
  UnpackResponse,
  ErrorResponse,
} from "../schemas/didcomm.js";
import {
  packEncrypted,
  packSigned,
  packPlaintext,
  unpack,
} from "../services/didcomm.js";

export async function didcommRoutes(fastify: TypedFastify) {
  fastify.post("/didcomm/pack/encrypted", {
    schema: {
      tags: ["DIDComm"],
      summary: "Pack an encrypted DIDComm message",
      body: PackEncryptedRequest,
      response: {
        200: PackEncryptedResponse,
        400: ErrorResponse,
      },
    },
    handler: async (request) => {
      return packEncrypted(request.body);
    },
  });

  fastify.post("/didcomm/pack/signed", {
    schema: {
      tags: ["DIDComm"],
      summary: "Pack a signed DIDComm message",
      body: PackSignedRequest,
      response: {
        200: PackSignedResponse,
        400: ErrorResponse,
      },
    },
    handler: async (request) => {
      return packSigned(request.body);
    },
  });

  fastify.post("/didcomm/pack/plaintext", {
    schema: {
      tags: ["DIDComm"],
      summary: "Pack a plaintext DIDComm message",
      body: PackPlaintextRequest,
      response: {
        200: PackPlaintextResponse,
        400: ErrorResponse,
      },
    },
    handler: async (request) => {
      return packPlaintext(request.body);
    },
  });

  fastify.post("/didcomm/unpack", {
    schema: {
      tags: ["DIDComm"],
      summary: "Unpack a DIDComm message",
      body: UnpackRequest,
      response: {
        200: UnpackResponse,
        400: ErrorResponse,
      },
    },
    handler: async (request) => {
      return unpack(request.body);
    },
  });
}
