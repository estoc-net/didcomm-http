# didcomm-http

HTTP wrapper for [didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) WASM and DID resolvers ([web-did-resolver](https://github.com/decentralized-identity/web-did-resolver) + [didwebvh-ts](https://github.com/decentralized-identity/didwebvh-ts)), built with Fastify.

Designed for Ruby (or any language) to call DIDComm pack/unpack and DID resolution via HTTP, with auto-generated OpenAPI spec for client generation.

## API Endpoints

### DIDComm (Stateless)

All DIDComm endpoints are stateless — caller provides DID docs and secrets in every request.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/didcomm/pack/encrypted` | Authenticated or anonymous encryption |
| POST | `/didcomm/pack/signed` | JWS signing (non-repudiation) |
| POST | `/didcomm/pack/plaintext` | Plaintext packing (debug only) |
| POST | `/didcomm/unpack` | Unpack any DIDComm message |

### DID Resolution

| Method | Path | Description |
|--------|------|-------------|
| POST | `/did/resolve` | Resolve did:web, did:webvh, did:peer:2 or did:peer:4 (long form) |
| POST | `/did/didcomm-doc` | Resolve a DID into the DIDDoc format the `/didcomm/*` endpoints accept |

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
| POST | `/did/peer/4/resolve-short` | Resolve a short form DID given its input document |

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

## Example: Pack & Unpack

```bash
# Pack encrypted (alice → bob)
curl -X POST http://localhost:3000/didcomm/pack/encrypted \
  -H 'Content-Type: application/json' \
  -d '{
    "message": {
      "id": "msg-1",
      "typ": "application/didcomm-plain+json",
      "type": "https://example.com/ping",
      "from": "did:example:alice",
      "to": ["did:example:bob"],
      "body": {"hello": "world"}
    },
    "to": "did:example:bob",
    "from": "did:example:alice",
    "didDocs": [ ... ],
    "secrets": [ ... ]
  }'

# Unpack
curl -X POST http://localhost:3000/didcomm/unpack \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "<packed JWE string>",
    "didDocs": [ ... ],
    "secrets": [ ... ]
  }'
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

## License

Apache-2.0
