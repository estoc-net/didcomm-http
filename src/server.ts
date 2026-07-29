import Fastify from "fastify";
import { Type } from "@sinclair/typebox";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";
import { didcommRoutes } from "./routes/didcomm.js";
import { didRoutes } from "./routes/did.js";
import { sharedSchemas } from "./schemas/shared.js";
import type { TypeBoxProvider } from "./types/fastify.js";
import { errorHandler } from "./plugins/error-handler.js";

export interface ServerOptions {
  /** Let /didcomm/send POST to private networks — development only. */
  allowPrivateDelivery?: boolean;
}

export async function buildServer(options: ServerOptions = {}) {
  const fastify = Fastify({
    logger: true,
    // The router's default cap on a path parameter is 100 chars, and a DID in
    // GET /did/{did} is routinely longer — a did:peer:2 with one service
    // already is. Anything longer than this belongs in POST /did/resolve.
    routerOptions: { maxParamLength: 8192 },
  }).withTypeProvider<TypeBoxProvider>();

  await fastify.register(swagger, {
    openapi: {
      info: {
        title: "DIDComm HTTP API",
        description:
          "HTTP wrapper for DIDComm WASM (didcomm-rust) and DID resolution (did:web + did:webvh + did:peer)",
        version: "1.0.0",
      },
      tags: [
        {
          name: "DIDComm",
          description: "Stateless DIDComm pack/unpack operations",
        },
        { name: "DID", description: "DID resolution" },
      ],
    },
    // A shared schema is named by its `$id` rather than by the order it was
    // reached in. The default is `def-0`, `def-1`, … — positional, so adding a
    // schema renames the ones after it, and a client generated from the
    // document gets its types renamed for a change that touched none of them.
    refResolver: { buildLocalReference: (json, _base, _fragment, i) => `${json.$id ?? `def-${i}`}` },
  });

  await fastify.register(swaggerUI, {
    routePrefix: "/documentation",
  });

  // Before any route, since a route holding a `$ref` is compiled against these
  // — for validating a request and for serializing a response both. A shape
  // named here is written into `components/schemas` once instead of being
  // copied out under every operation that uses it.
  for (const schema of sharedSchemas) fastify.addSchema(schema);

  fastify.setErrorHandler(errorHandler);

  // Everything below /v1 is the API's contract; /health and /openapi.json
  // describe the server itself and stay unversioned.
  await fastify.register(didcommRoutes, {
    prefix: "/v1",
    allowPrivateDelivery: options.allowPrivateDelivery ?? false,
  });
  await fastify.register(didRoutes, { prefix: "/v1" });

  // Answering at all is the whole test: the WASM is loaded at import time, so a
  // server that is listening is a server that can pack.
  fastify.get("/health", {
    schema: {
      tags: ["DID"],
      summary: "Liveness check",
      response: { 200: Type.Object({ status: Type.Literal("ok") }) },
    },
    handler: async () => ({ status: "ok" as const }),
  });

  fastify.get("/openapi.json", {
    schema: { hide: true },
    handler: async () => {
      return fastify.swagger();
    },
  });

  return fastify;
}
