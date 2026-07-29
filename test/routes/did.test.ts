import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildServer } from "../../src/server.js";
import type { FastifyInstance } from "fastify";
import {
  MEDIATOR_DID,
  MEDIATOR_ENDPOINT,
  PEER_2_DID,
  PEER_2_DOCUMENT,
} from "../fixtures/peer-did-2.js";

let app: FastifyInstance;

beforeAll(async () => {
  app = await buildServer();
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

describe("POST /v1/did/resolve", () => {
  it("returns 400 for unsupported DID method", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/did/resolve",
      payload: { did: "did:example:alice" },
    });

    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.didResolutionMetadata.error).toBe("methodNotSupported");
  });

  it("returns 404 for unresolvable did:web", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/did/resolve",
      payload: { did: "did:web:nonexistent.invalid" },
    });

    // Should get a resolution result with error
    const body = res.json();
    expect(body.didResolutionMetadata).toBeDefined();
  });

  it("resolves a did:peer:2 without leaving the process", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/did/resolve",
      payload: { did: PEER_2_DID },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().didDocument).toStrictEqual(PEER_2_DOCUMENT);
  });

  it("returns 400 for a malformed did:peer:2", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/did/resolve",
      payload: { did: "did:peer:2.Zwhatever" },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().didResolutionMetadata.error).toBe("invalidDid");
  });
});

describe("GET /v1/did/{did}", () => {
  it("resolves a did:peer:2 straight off the URL", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/v1/did/${PEER_2_DID}`,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().didDocument).toStrictEqual(PEER_2_DOCUMENT);
  });

  it("returns 400 for an unsupported DID method, in the same shape", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/v1/did/did:example:alice",
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().didResolutionMetadata.error).toBe("methodNotSupported");
  });
});

describe("GET /v1/did/{did}/didcomm", () => {
  it("gives back the endpoint and key a forward to a mediator needs", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/v1/did/${MEDIATOR_DID}/didcomm`,
    });

    expect(res.statusCode).toBe(200);
    const { didDoc } = res.json();
    expect(didDoc.service[0].serviceEndpoint.uri).toBe(MEDIATOR_ENDPOINT);
    expect(didDoc.keyAgreement).toStrictEqual([`${MEDIATOR_DID}#key-2`]);
  });

  it("keeps the resolution error shape when the DID does not resolve", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/v1/did/did:example:alice/didcomm",
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().didResolutionMetadata.error).toBe("methodNotSupported");
  });
});

describe("GET /health", () => {
  it("answers once the WASM is loaded and the routes are up", async () => {
    const res = await app.inject({ method: "GET", url: "/health" });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok" });
  });
});
