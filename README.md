# didcomm-http

HTTP wrapper for [didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) WASM and DID resolvers ([web-did-resolver](https://github.com/decentralized-identity/web-did-resolver) + [didwebvh-ts](https://github.com/decentralized-identity/didwebvh-ts)), built with Fastify.

Designed for Ruby (or any language) to call DIDComm pack/unpack and DID resolution via HTTP, with auto-generated OpenAPI spec for client generation.

## API Endpoints

### DIDComm

| Method | Path | Description |
|--------|------|-------------|
| POST | `/didcomm/pack/encrypted` | Authenticated or anonymous encryption, routed |
| POST | `/didcomm/pack/signed` | JWS signing (non-repudiation) |
| POST | `/didcomm/pack/plaintext` | Plaintext packing (debug only) |
| POST | `/didcomm/unpack` | Unpack any DIDComm message |

Only secrets are stateful, and only for the length of a request: a caller sends
the private keys it wants used and the server keeps none of them.

Documents are a different matter — they are **resolved**, not supplied. Every
method below resolves, including a mediator standing in front of a recipient, so
packing a message needs nothing but the DID it is going to. `didDocs` is still
accepted and now means *pinning*: a document listed there is used exactly as
given and never fetched. Two things need it — a document published nowhere, such
as a short form `did:peer:4` only its holder can expand, and a DID whose
published document is not the one you hold the keys for, which is what a
`did:web` looks like from a development checkout.

#### Where a packed message goes

`/didcomm/pack/encrypted` always answers with a `deliveryEndpoint`:

```jsonc
{
  "packedMessage": "{ JWE }",
  "deliveryEndpoint": "https://mediator.example/message",
  "metadata": { "from_kid": "…", "to_kids": ["…"] }
}
```

It is the mediator's address when the message was wrapped in a Forward, the
recipient's own when it was not, and `null` when the recipient publishes no
DIDComm endpoint at all — an agent that can only be answered on a connection it
opened. `options.forward` defaults to `true`, which is the spec's default and
the only one that reaches an agent behind a mediator; pass `false` for a message
going straight back down an open connection, where a Forward would arrive at the
one party that cannot read it.

#### Who a message is from

`/didcomm/unpack` reports the claim and the proof apart:

```jsonc
{
  "message": { "from": "did:web:merely.ca", "…": "…" },
  "from": "did:web:merely.ca",
  "verifiedFrom": "did:peer:4zQm…",
  "senderVerified": false,
  "encrypted": true,
  "metadata": { "…": "…" }
}
```

Opening an envelope proves whose key closed it. It proves nothing about the
`from` written inside, and didcomm-rust never compares the two — a sender is
free to authcrypt with their own key under somebody else's name. `senderVerified`
is the two agreeing, and it is the only one of the three worth trusting.

### DID Resolution

| Method | Path | Description |
|--------|------|-------------|
| POST | `/did/resolve` | Resolve did:web, did:webvh, did:peer:2 or did:peer:4 (long form) |
| POST | `/did/didcomm-doc` | Resolve a DID into the DIDDoc format the `/didcomm/*` endpoints accept |
| GET | `/health` | Liveness |

Fetched documents (`did:web`, `did:webvh`) are cached for `DID_CACHE_TTL`
seconds. A `did:peer` is decoded rather than fetched, so it is never cached and
a stranger introducing themselves cannot push out the mediators and
correspondents that were worth keeping.

### did:peer:2

Resolving a `did:peer:2` is decoding it: the keys and services are in the
identifier, so nothing is fetched and nothing can be stale. There is no create
endpoint to match `/did/peer/4` — whoever holds the keys assembles the string.

It is here because mediators are named that way. An agent behind one publishes
the mediator's DID as its service endpoint, so a message addressed to that agent
cannot be routed, and a message from it cannot be unpacked, unless this method
resolves.

### did:peer:4

| Method | Path | Description |
|--------|------|-------------|
| POST | `/did/peer/4` | Derive long + short form DIDs from an input document |
| POST | `/did/peer/4/create` | Generate keys and the DID that names them |
| POST | `/did/peer/4/resolve-short` | Resolve a short form DID given its input document |

`/did/peer/4/create` is `/did/peer/4` without having to build the input document
first: it generates an Ed25519 and an X25519 key, publishes the service endpoint
you name, and hands back the DID along with the secrets to use it. The private
keys are in the response, so it suits an identity meant to be temporary — a
test, a demo, one side of a conversation nobody will resume. A DID that stands
for somebody generates its keys where they will live.

`/did/peer/4` returns `didcommDidDoc` alongside the W3C documents, ready to pass
straight into `/didcomm/*`. Resolution follows the spec and keeps references
relative (`#key-1`); the DIDComm DIDDoc conversion absolutizes them, which
didcomm-rust requires because it derives a DID by splitting a `kid` on `#`.

A short form `did:peer:4` carries no document, so `/did/resolve` returns 404 for
it — use `/did/peer/4/resolve-short` with the input document instead.

### OpenAPI

| Path | Description |
|------|-------------|
| `/documentation` | Swagger UI |
| `/openapi.json` | OpenAPI 3.0 spec |

## Quick Start

```bash
npm install
npm run dev
```

Server starts at `http://localhost:3000`. Visit `http://localhost:3000/documentation` for Swagger UI.

## Scripts

```bash
npm run dev            # Development with hot reload
npm run start          # Production start
npm test               # Run tests
npm run test:watch     # Run tests in watch mode
npm run openapi:export # Export OpenAPI spec to stdout
```

## Example: a whole conversation

Two identities, a message from one to the other, and the other reading it —
without a DID document changing hands, because a `did:peer:4` *is* its document.

```bash
# Alice, who can send but has no address of her own
ALICE=$(curl -sX POST localhost:3000/did/peer/4/create -H 'Content-Type: application/json' -d '{}')

# Bob, who publishes somewhere to be written to
BOB=$(curl -sX POST localhost:3000/did/peer/4/create -H 'Content-Type: application/json' \
  -d '{"service": "https://bob.example/didcomm"}')

# Pack. The answer says where it goes: https://bob.example/didcomm
curl -sX POST localhost:3000/didcomm/pack/encrypted -H 'Content-Type: application/json' -d "{
  \"message\": {
    \"id\": \"msg-1\",
    \"typ\": \"application/didcomm-plain+json\",
    \"type\": \"https://didcomm.org/basicmessage/2.0/message\",
    \"from\": $(jq .did <<<"$ALICE"),
    \"to\": [$(jq .did <<<"$BOB")],
    \"body\": {\"content\": \"hello\"}
  },
  \"to\": $(jq .did <<<"$BOB"),
  \"from\": $(jq .did <<<"$ALICE"),
  \"secrets\": $(jq .secrets <<<"$ALICE")
}"

# Unpack, with Bob's keys and nothing else
curl -sX POST localhost:3000/didcomm/unpack -H 'Content-Type: application/json' -d "{
  \"message\": $(jq -Rs . <<<"$PACKED"),
  \"secrets\": $(jq .secrets <<<"$BOB")
}"
```

## Docker

```bash
docker run -p 3000:3000 onyxblade/didcomm-http
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Listen address |
| `PORT` | `3000` | Listen port |
| `DID_CACHE_TTL` | `300` | Seconds a fetched DID document is reused |

## License

Apache-2.0
