# CLAUDE.md

## Commands
- `npm run dev` — Start dev server (tsx watch)
- `npm test` — Run tests (vitest)
- `npm run typecheck` — TypeScript type check (tsc --noEmit)
- `npm run openapi:export` — Export OpenAPI spec to stdout

## Architecture
- **Fastify 5 + TypeScript ESM** with a TypeBox type provider for type-safe routes
- All API routes live under `/v1`; `/health` and `/openapi.json` describe the server and stay unversioned. Naming rule: DIDComm wire-format fields keep the spec's snake_case (`created_time`, `from_prior`, attachment fields), everything that is this API's own (options, metadata) is camelCase. The seam is `src/services/didcomm.ts`, which maps to and from didcomm-rust's snake_case — neither casing leaks through it
- `GET /v1/did/{did}` reads the DID **verbatim off the raw path**, not from the decoded route param: `%3A` in `did:web:example.com%3A8080` is part of the DID, and decoding would collapse it into a different DID. `maxParamLength` is raised to 8192 because DIDs blow past find-my-way's 100-char default (a did:peer:2 with one service already does); `POST /v1/did/resolve` is the fallback for longer ones. Resolution errors — including from `GET /v1/did/{did}/didcomm` — always answer in the `DIDResolutionResult` shape, so a caller handles failure once
- `POST /v1/didcomm/send` packs and then POSTs to the `deliveryEndpoint`. `src/services/delivery.ts` refuses private networks (loopback, RFC 1918, link-local, CGNAT, v4-mapped v6) **twice**: a pre-flight DNS check that names the address (400 `DeliveryRefused`), and a filtered `lookup` inside the undici Agent's connector, which closes DNS rebinding because the address checked is the address dialed. `ALLOW_PRIVATE_DELIVERY=true` (or `buildServer({ allowPrivateDelivery: true })`, which the send tests use) lifts the network policy only — scheme and URL checks stay
- **@sinclair/typebox** for JSON Schema definitions — drives both validation and OpenAPI generation
- A shape more than one operation uses goes through `shared()` in `src/schemas/shared.ts`, which names it and returns the reference every use goes through. `server.ts` registers all of them before the first route, and passes a `refResolver` so the document names them by `$id` rather than by the positional `def-0` default, which would renumber the rest whenever one is added. Without any of this every operation carries its own copy of the shape, and a generated client gets a type per copy: the message packed encrypted and the one packed signed become two unrelated types, and no caller can build one message and pack it both ways. Do not name a branch of an undiscriminated union (`ServiceEndpoint`) — a client cannot tell which branch it holds, so the name would be reachable from nothing
- Routes take `TypedFastify` from `src/types/fastify.ts` rather than `@fastify/type-provider-typebox`'s provider. That one inlines its conditional over the deferred `this['schema']`, and a `Type.Ref` does not survive it: every referenced property arrives at the handler as `unknown`, though `Static` infers the same schema exactly outside a route. Ours passes the deferred type through a named alias, which resolves it
- **didcomm-node** (CJS) for DIDComm WASM — NOT `didcomm` (ESM), which requires `--experimental-wasm-modules`
- DIDComm endpoints **resolve DID documents themselves** (`ChainedResolver` in `src/services/didcomm.ts`): `didDocs` is optional and *pins* — a listed document is used as given and never fetched. Secrets are always the caller's to send, and none are kept
- `packEncrypted` defaults `forward` to `true` and always returns `deliveryEndpoint`. didcomm-rust reports `metadata.messaging_service` **only when it actually wrapped a forward**, so a directly reachable recipient needs the `deliveryEndpoint()` fallback — do not delete it
- `unpack` reports `from` (claimed) and `verifiedFrom` (proven) apart, because didcomm-rust compares `message.from` against the sending key only when **packing**. An envelope from another implementation can claim anyone; `senderVerified` is the comparison
- `src/services/identity.ts` generates keys for `/v1/did/peer/4/generate`. Secret ids must be absolutized against the DID, since didcomm-rust matches a secret to a verification method by id. `/v1/did/peer/4/encode` is the keys-stay-home counterpart: document in, DIDs out
- **did:peer:4** is implemented in-tree (`src/services/did-peer-4.ts`), ported from `references/did-peer-4-ts` — the upstream package is not published to npm. `varint` is dropped; both multicodec prefixes are constants
- **did:peer:2** is implemented in-tree too (`src/services/did-peer-2.ts`) — resolution only, since the document is encoded in the DID. Needed because mediators are named by did:peer:2, so routing to (and unpacking from) a mediated agent depends on it
- `src/services/did-doc.ts` converts W3C DID documents into the flat didcomm-rust DIDDoc shape

## Code Conventions
- No `as` type assertions in `src/` — use proper types, type providers, or normalize at boundaries
- WASM `PackSignedMetadata.sign_by_kid` is typed as `String` (wrapper object) — normalize with `String()` to primitive
- WASM returns `null` (not `undefined`) for absent optional fields — use `toBeFalsy()` in tests, not `toBeUndefined()`
- ...and a `null` that reaches fast-json-stringify is serialized as the **empty value of its schema type**, not omitted: `""` for a string, `{}` for an object. Every WASM metadata object goes through `stated()` in `src/services/didcomm.ts` before being returned, or an unsigned message ships `signByKid: ""` and an unforwarded one ships `messagingService: {}` — both of which the schema says cannot happen. A service-level test cannot see this; assert it on `res.json()` in `test/routes/`
- Routes use `TypedFastify` type alias with `TypeBoxTypeProvider` for automatic body/params inference
- DID resolution error responses return `DIDResolutionResult` (not `ErrorResponse`) with appropriate HTTP status — from the `/didcomm` conversion variant too
- didcomm-rust has no `Multikey` verification method type — `toDIDCommDIDDoc` remaps it to the 2020 suite via the multicodec prefix
- didcomm-rust's `VerificationMethodType` has no catch-all deserializer, so an unknown type string fails the **whole** DIDDoc — `toDIDCommDIDDoc` maps anything unrecognized to `Other`
- did:peer:4 resolution keeps references relative per the spec; absolutization happens only in `toDIDCommDIDDoc` (verification methods, relationships, service ids, and `routingKeys`)
- `validateInputDocument` runs on create only, never on resolve: did:peer:4 is self-certifying, so rejecting a counterparty's non-conformant document would cost interoperability for nothing

## Project Structure
```
src/
  schemas/     — TypeBox schemas (did.ts, didcomm.ts) + shared.ts, the named ones
  types/       — fastify.ts: the type provider and the TypedFastify alias
  services/    — Business logic (didcomm.ts, did-resolver.ts)
  routes/      — Fastify routes (didcomm.ts, did.ts)
  plugins/     — Error handler
  server.ts    — Fastify setup + swagger + plugin registration
  index.ts     — Entry point
scripts/       — OpenAPI export
test/
  fixtures/    — Test vectors from references/didcomm-rust
  services/    — Service unit tests
  routes/      — Route integration tests (Fastify inject)
references/    — Git submodules (didcomm-rust, didwebvh-ts, web-did-resolver, etc.)
```

## Testing
- vitest.config.ts excludes `references/**` to avoid picking up reference submodule tests
- Test fixtures come from `references/didcomm-rust/wasm/tests-js/src/test-vectors/`
- Route tests use `app.inject()` (no real HTTP server needed)

## Gotchas
- `tsconfig.json` rootDir is `.` (not `src/`) because `scripts/` also needs to compile
- `punycode` deprecation warning from didwebvh-ts is harmless
