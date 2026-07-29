import { lookup } from "node:dns";
import dns from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import type { LookupFunction } from "node:net";
import type { ReadableStream } from "node:stream/web";
import { Agent, fetch } from "undici";

/** The endpoint cannot be delivered to and retrying will not change that. */
export class DeliveryRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeliveryRefused";
  }
}

/** The endpoint did not answer; the network, not the request, is at fault. */
export class DeliveryFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeliveryFailed";
  }
}

/**
 * Everything that is not the public internet.
 *
 * A DID document is the counterparty's to write, so its service endpoint is an
 * attacker-supplied URL, and a server that POSTs wherever it points is a proxy
 * into whatever network it was deployed on. Loopback, RFC 1918, link-local
 * (cloud metadata lives there), CGNAT and benchmark ranges are all refused;
 * `allowPrivate` (for development against a local mediator) is the only way in.
 */
const PRIVATE_RANGES = new BlockList();
PRIVATE_RANGES.addSubnet("0.0.0.0", 8);
PRIVATE_RANGES.addSubnet("10.0.0.0", 8);
PRIVATE_RANGES.addSubnet("100.64.0.0", 10);
PRIVATE_RANGES.addSubnet("127.0.0.0", 8);
PRIVATE_RANGES.addSubnet("169.254.0.0", 16);
PRIVATE_RANGES.addSubnet("172.16.0.0", 12);
PRIVATE_RANGES.addSubnet("192.0.0.0", 24);
PRIVATE_RANGES.addSubnet("192.168.0.0", 16);
PRIVATE_RANGES.addSubnet("198.18.0.0", 15);
PRIVATE_RANGES.addSubnet("224.0.0.0", 3);
PRIVATE_RANGES.addSubnet("::", 128, "ipv6");
PRIVATE_RANGES.addSubnet("::1", 128, "ipv6");
// Dotted v4-mapped notation is unwrapped and judged as its IPv4; this catches
// the hex spelling of the same range, at the price of refusing public hosts
// that publish themselves that way — which nobody reachable honestly does.
PRIVATE_RANGES.addSubnet("::ffff:0:0", 96, "ipv6");
PRIVATE_RANGES.addSubnet("fc00::", 7, "ipv6");
PRIVATE_RANGES.addSubnet("fe80::", 10, "ipv6");

function isPrivateAddress(address: string): boolean {
  const family = isIP(address);

  if (family === 4) {
    return PRIVATE_RANGES.check(address, "ipv4");
  }

  if (family === 6) {
    // An IPv4-mapped address reaches the IPv4 host it embeds, so it is
    // whatever that host is.
    const mapped = address.toLowerCase().startsWith("::ffff:")
      ? address.slice("::ffff:".length)
      : null;

    if (mapped !== null && isIP(mapped) === 4) {
      return isPrivateAddress(mapped);
    }

    return PRIVATE_RANGES.check(address, "ipv6");
  }

  // Not an address at all.
  return true;
}

/**
 * The pre-flight check names the address it refused and becomes a 400; this
 * one exists because a check-then-connect can be lied to — a resolver free to
 * answer differently twice can pass the check with a public address and hand
 * the connection a private one. Filtering inside the socket's own lookup
 * closes that, because the address checked is the address dialed.
 */
const guardedLookup: LookupFunction = (hostname, options, callback) => {
  lookup(hostname, options, (err, addresses, family) => {
    if (err !== null) {
      callback(err, addresses, family);
      return;
    }

    const found = (
      Array.isArray(addresses) ? addresses.map((entry) => entry.address) : [addresses]
    ).find(isPrivateAddress);

    if (found !== undefined) {
      callback(
        new Error(`${hostname} resolves to a private address (${found})`),
        addresses,
        family
      );
      return;
    }

    callback(null, addresses, family);
  });
};

const guardedAgent = new Agent({ connect: { lookup: guardedLookup } });
const openAgent = new Agent();

const DELIVERY_TIMEOUT_MS = 10_000;
const RESPONSE_LIMIT = 8_192;

/** URL hostnames wrap IPv6 in brackets; addresses everywhere else do not. */
function hostnameAddress(url: URL): string {
  return url.hostname.startsWith("[") && url.hostname.endsWith("]")
    ? url.hostname.slice(1, -1)
    : url.hostname;
}

async function assertDeliverable(url: URL): Promise<void> {
  const host = hostnameAddress(url);

  const addresses = isIP(host)
    ? [host]
    : (await dns.lookup(host, { all: true })).map((entry) => entry.address);

  const found = addresses.find(isPrivateAddress);
  if (found !== undefined) {
    throw new DeliveryRefused(
      `${url.origin} is not on the public internet (${found}); ` +
        "delivery to private networks is off unless the server enables it"
    );
  }
}

function rootCause(err: unknown): string {
  if (err instanceof Error) {
    return err.cause !== undefined ? rootCause(err.cause) : err.message;
  }

  return String(err);
}

/** The first bytes of the body, without agreeing to read all of it. */
async function responsePrefix(
  body: ReadableStream<Uint8Array> | null
): Promise<string> {
  if (body === null) {
    return "";
  }

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = "";

  while (text.length < RESPONSE_LIMIT) {
    const { done, value } = await reader.read();
    if (done) {
      return text.slice(0, RESPONSE_LIMIT);
    }
    text += decoder.decode(value, { stream: true });
  }

  await reader.cancel().catch(() => undefined);
  return text.slice(0, RESPONSE_LIMIT);
}

export interface DeliveryReceipt {
  status: number;
  response?: string;
}

/**
 * POST a packed message to the endpoint its packing chose.
 *
 * The recipient's answer is reported, not judged: their 4xx is a delivered
 * request and comes back as data. Only this server's own failures are thrown —
 * an endpoint that is not deliverable at all (`DeliveryRefused`, 400) or one
 * that could not be reached (`DeliveryFailed`, 502).
 */
export async function deliver(
  endpoint: string,
  packedMessage: string,
  { allowPrivate = false }: { allowPrivate?: boolean } = {}
): Promise<DeliveryReceipt> {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new DeliveryRefused(`${endpoint} is not a URL`);
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new DeliveryRefused(`${endpoint} is not an HTTP endpoint`);
  }

  if (!allowPrivate) {
    try {
      await assertDeliverable(url);
    } catch (err) {
      if (err instanceof DeliveryRefused) {
        throw err;
      }
      throw new DeliveryFailed(`could not resolve ${url.hostname}: ${rootCause(err)}`);
    }
  }

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/didcomm-encrypted+json" },
      body: packedMessage,
      dispatcher: allowPrivate ? openAgent : guardedAgent,
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
    });

    const response = await responsePrefix(res.body);
    return response === ""
      ? { status: res.status }
      : { status: res.status, response };
  } catch (err) {
    throw new DeliveryFailed(`POST ${url.origin} failed: ${rootCause(err)}`);
  }
}
