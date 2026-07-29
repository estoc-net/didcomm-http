import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { FastifyInstance } from "fastify";
import { buildServer } from "../../src/server.js";
import { createIdentity } from "../../src/services/identity.js";

let app: FastifyInstance; // delivers to private networks, as a dev setup would
let strictApp: FastifyInstance; // the default posture
let inbox: Server;
let inboxURL: string;

const received: { body: string; contentType: string | undefined }[] = [];

function messageTo(did: string) {
  return {
    id: "send-1",
    typ: "application/didcomm-plain+json",
    type: "https://didcomm.org/basicmessage/2.0/message",
    to: [did],
    body: { content: "好" },
  };
}

beforeAll(async () => {
  app = await buildServer({ allowPrivateDelivery: true });
  await app.ready();

  strictApp = await buildServer();
  await strictApp.ready();

  inbox = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      received.push({ body, contentType: req.headers["content-type"] });
      res.statusCode = 202;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ accepted: true }));
    });
  });

  await new Promise<void>((resolve) => {
    inbox.listen(0, "127.0.0.1", resolve);
  });

  const address = inbox.address();
  if (address === null || typeof address === "string") {
    throw new Error("inbox has no port");
  }
  inboxURL = `http://127.0.0.1:${address.port}/inbox`;
});

afterAll(async () => {
  await app.close();
  await strictApp.close();
  await new Promise((resolve) => inbox.close(resolve));
});

describe("POST /v1/didcomm/send", () => {
  it("packs and POSTs to the recipient's endpoint, reporting their answer", async () => {
    const bob = createIdentity(["X25519"], inboxURL);

    const res = await app.inject({
      method: "POST",
      url: "/v1/didcomm/send",
      payload: { message: messageTo(bob.did), to: bob.did },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();

    expect(body.deliveryEndpoint).toBe(inboxURL);
    expect(body.delivery.status).toBe(202);
    expect(body.delivery.response).toBe('{"accepted":true}');

    // What arrived is exactly what was packed, said to be what it is.
    const delivered = received.at(-1);
    expect(delivered?.body).toBe(body.packedMessage);
    expect(delivered?.contentType).toBe("application/didcomm-encrypted+json");
  });

  it("400s when the recipient publishes no endpoint at all", async () => {
    const bob = createIdentity(["X25519"]);

    const res = await app.inject({
      method: "POST",
      url: "/v1/didcomm/send",
      payload: { message: messageTo(bob.did), to: bob.did },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("NoDeliveryEndpoint");
  });

  it("refuses private networks unless the server opted in", async () => {
    const bob = createIdentity(["X25519"], inboxURL);

    const res = await strictApp.inject({
      method: "POST",
      url: "/v1/didcomm/send",
      payload: { message: messageTo(bob.did), to: bob.did },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("DeliveryRefused");
  });

  it("502s when the endpoint cannot be reached", async () => {
    // A port nobody is listening on: refused, not refused-by-policy.
    const bob = createIdentity(["X25519"], "http://127.0.0.1:9/inbox");

    const res = await app.inject({
      method: "POST",
      url: "/v1/didcomm/send",
      payload: { message: messageTo(bob.did), to: bob.did },
    });

    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("DeliveryFailed");
  });
});
