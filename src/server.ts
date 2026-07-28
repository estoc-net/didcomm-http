import Fastify from "fastify";
import { Type } from "@sinclair/typebox";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";
import { didcommRoutes } from "./routes/didcomm.js";
import { didRoutes } from "./routes/did.js";
import { sharedSchemas } from "./schemas/shared.js";
import type { TypeBoxProvider } from "./types/fastify.js";
import { errorHandler } from "./plugins/error-handler.js";

export async function buildServer() {
  const fastify = Fastify({
    logger: true,
  }).withTypeProvider<TypeBoxProvider>();

  await fastify.register(swagger, {
    openapi: {
      info: {
        title: "DIDComm HTTP API",
        description:
          "HTTP wrapper for DIDComm WASM (didcomm-rust) and DID resolution (did:web + did:webvh)",
        version: "0.1.0",
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

  await fastify.register(didcommRoutes);
  await fastify.register(didRoutes);

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
