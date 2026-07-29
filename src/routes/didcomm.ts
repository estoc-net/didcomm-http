import type { TypedFastify } from "../types/fastify.js";
import {
  PackEncryptedRequest,
  PackEncryptedResponse,
  PackSignedRequest,
  PackSignedResponse,
  PackPlaintextRequest,
  PackPlaintextResponse,
  SendRequest,
  SendResponse,
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
import { deliver } from "../services/delivery.js";

export interface DIDCommRoutesOptions {
  /**
   * Let /didcomm/send POST to private networks — for development against a
   * mediator on localhost. In production this stays off, or the server is a
   * proxy into its own network for anyone who can write a DID document.
   */
  allowPrivateDelivery?: boolean;
}

export async function didcommRoutes(
  fastify: TypedFastify,
  { allowPrivateDelivery = false }: DIDCommRoutesOptions
) {
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

  fastify.post("/didcomm/send", {
    schema: {
      tags: ["DIDComm"],
      summary: "Pack an encrypted DIDComm message and deliver it",
      description:
        "Packs exactly as /didcomm/pack/encrypted does, then POSTs the result to its deliveryEndpoint. The recipient's HTTP answer is reported as data, whatever it was; only this server's own failures are errors — a recipient with no endpoint (400) or one that could not be reached (502).",
      body: SendRequest,
      response: {
        200: SendResponse,
        400: ErrorResponse,
        502: ErrorResponse,
      },
    },
    handler: async (request, reply) => {
      const { packedMessage, deliveryEndpoint, metadata } = await packEncrypted(
        request.body
      );

      if (deliveryEndpoint === null) {
        return reply.status(400).send({
          error: "NoDeliveryEndpoint",
          message: `${request.body.to} publishes no DIDComm endpoint, so there is nowhere to deliver to`,
        });
      }

      const delivery = await deliver(deliveryEndpoint, packedMessage, {
        allowPrivate: allowPrivateDelivery,
      });

      return { packedMessage, deliveryEndpoint, metadata, delivery };
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
