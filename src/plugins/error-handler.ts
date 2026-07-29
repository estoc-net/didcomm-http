import type { FastifyError, FastifyReply, FastifyRequest } from "fastify";

const DIDCOMM_ERROR_STATUS: Record<string, number> = {
  DIDCommDIDNotResolved: 404,
  DIDCommDIDUrlNotFound: 404,
  DIDCommSecretNotFound: 400,
  DIDCommMalformed: 400,
  DIDCommIllegalArgument: 400,
  DIDCommNoCompatibleCrypto: 400,
  DIDCommUnsupported: 400,
  DIDCommIoError: 502,
  DIDCommInvalidState: 500,
  DeliveryRefused: 400,
  DeliveryFailed: 502,
};

export function errorHandler(
  error: FastifyError | Error,
  _request: FastifyRequest,
  reply: FastifyReply
) {
  const errorName = error.name ?? "UnknownError";
  const status = DIDCOMM_ERROR_STATUS[errorName] ?? ("statusCode" in error ? error.statusCode : 500);

  reply.status(status ?? 500).send({
    error: errorName,
    message: error.message,
  });
}
