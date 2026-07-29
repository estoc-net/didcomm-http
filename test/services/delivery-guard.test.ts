import { describe, it, expect } from "vitest";
import { createServer } from "node:http";
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

  // IPv6 is an allowlist — global unicast or nothing — so the ranges nobody
  // thought to blocklist are refused too.
  it("deprecated site-local IPv6, which intranets still route", () =>
    refused("http://[fec0::1]:3000/didcomm"));

  it("IPv6 multicast", () => refused("http://[ff02::1]:3000/didcomm"));

  it("the IPv6 documentation range", () =>
    refused("http://[2001:db8::1]:3000/didcomm"));

  // Global unicast is not all public: IANA carves special ranges out of
  // 2000::/3 itself, and these are refused at the boundary rather than left
  // to time out as unroutable.
  it("the IPv6 benchmarking range, as the IPv4 list already does", () =>
    refused("http://[2001:2::1]:3000/didcomm"));

  it("6to4, an IPv4 address in IPv6 clothes — this one wears loopback's", () =>
    refused("http://[2002:7f00:1::1]:3000/didcomm"));

  it("Teredo, which embeds an IPv4 address the same way", () =>
    refused("http://[2001::a]:3000/didcomm"));

  it("the newer documentation range, 3fff::/20", () =>
    refused("http://[3fff::1]:3000/didcomm"));

  it("SRv6 SIDs, which name a route rather than a host", () =>
    refused("http://[5f00::1]:3000/didcomm"));

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

  it("reports a redirect instead of following it", async () => {
    // The vetted address is the dialed address; a followed redirect would be
    // neither, so it comes back as data. The Location points at a dead port —
    // following it would fail loudly, which is how this test would catch it.
    let hits = 0;
    const server = createServer((req, res) => {
      hits += 1;
      res.statusCode = 302;
      res.setHeader("location", "http://127.0.0.1:9/didcomm");
      res.end();
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("redirecting server has no port");
    }

    try {
      const receipt = await deliver(
        `http://127.0.0.1:${address.port}/didcomm`,
        "{}",
        { allowPrivate: true }
      );

      expect(receipt.status).toBe(302);
      expect(hits).toBe(1);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
