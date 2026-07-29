import { describe, it, expect } from "vitest";
import {
  deliver,
  DeliveryFailed,
  DeliveryRefused,
} from "../../src/services/delivery.js";

// None of these leave the machine: every one is refused before a connection
// is attempted, or aimed at a loopback port nobody listens on.
describe("what deliver refuses to touch", () => {
  const refused = (endpoint: string) =>
    expect(deliver(endpoint, "{}")).rejects.toBeInstanceOf(DeliveryRefused);

  it("link-local addresses, where cloud metadata lives", () =>
    refused("http://169.254.169.254/latest/meta-data"));

  it("RFC 1918 addresses", () => refused("http://10.0.0.5/didcomm"));

  it("loopback, by address", () => refused("http://127.0.0.1:3000/didcomm"));

  it("loopback, by name — the check runs on what the name resolves to", () =>
    refused("http://localhost:3000/didcomm"));

  it("IPv6 loopback", () => refused("http://[::1]:3000/didcomm"));

  it("IPv4 hidden inside an IPv6 mapping", () =>
    refused("http://[::ffff:127.0.0.1]:3000/didcomm"));

  it("schemes that are not HTTP", () =>
    refused("wss://example.com/didcomm"));

  it("things that are not URLs at all", () => refused("not-an-endpoint"));

  it("everything above, even when private delivery is allowed", async () => {
    // allowPrivate lifts the network policy, not the shape of an endpoint.
    await expect(
      deliver("wss://example.com/didcomm", "{}", { allowPrivate: true })
    ).rejects.toBeInstanceOf(DeliveryRefused);
  });

  it("reports an endpoint that answers nobody as failed, not refused", async () => {
    await expect(
      deliver("http://127.0.0.1:9/didcomm", "{}", { allowPrivate: true })
    ).rejects.toBeInstanceOf(DeliveryFailed);
  });
});
