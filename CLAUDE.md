# CLAUDE.md

## Commands
- `npm run dev` — Start dev server (tsx watch)
- `npm test` — Run tests (vitest)
- `npm run typecheck` — TypeScript type check (tsc --noEmit)
- `npm run openapi:export` — Export OpenAPI spec to stdout

## Architecture
- **Fastify 5 + TypeScript ESM** with `@fastify/type-provider-typebox` for type-safe routes
- **@sinclair/typebox** for JSON Schema definitions — drives both validation and OpenAPI generation
- **didcomm-node** (CJS) for DIDComm WASM — NOT `didcomm` (ESM), which requires `--experimental-wasm-modules`
- DIDComm endpoints **resolve DID documents themselves** (`ChainedResolver` in `src/services/didcomm.ts`): `didDocs` is optional and *pins* — a listed document is used as given and never fetched. Secrets are always the caller's to send, and none are kept
- `packEncrypted` defaults `forward` to `true` and always returns `deliveryEndpoint`. didcomm-rust reports `metadata.messaging_service` **only when it actually wrapped a forward**, so a directly reachable recipient needs the `deliveryEndpoint()` fallback — do not delete it
- `unpack` reports `from` (claimed) and `verifiedFrom` (proven) apart, because didcomm-rust compares `message.from` against the sending key only when **packing**. An envelope from another implementation can claim anyone; `senderVerified` is the comparison
- `src/services/identity.ts` generates keys for `/did/peer/4/create`. Secret ids must be absolutized against the DID, since didcomm-rust matches a secret to a verification method by id
- **did:peer:4** is implemented in-tree (`src/services/did-peer-4.ts`), ported from `references/did-peer-4-ts` — the upstream package is not published to npm. `varint` is dropped; both multicodec prefixes are constants
- **did:peer:2** is implemented in-tree too (`src/services/did-peer-2.ts`) — resolution only, since the document is encoded in the DID. Needed because mediators are named by did:peer:2, so routing to (and unpacking from) a mediated agent depends on it
- `src/services/did-doc.ts` converts W3C DID documents into the flat didcomm-rust DIDDoc shape

## Code Conventions
- No `as` type assertions in `src/` — use proper types, type providers, or normalize at boundaries
- WASM `PackSignedMetadata.sign_by_kid` is typed as `String` (wrapper object) — normalize with `String()` to primitive
- WASM returns `null` (not `undefined`) for absent optional fields — use `toBeFalsy()` in tests, not `toBeUndefined()`
- Routes use `TypedFastify` type alias with `TypeBoxTypeProvider` for automatic body/params inference
- DID resolution error responses return `DIDResolutionResult` (not `ErrorResponse`) with appropriate HTTP status
- didcomm-rust has no `Multikey` verification method type — `toDIDCommDIDDoc` remaps it to the 2020 suite via the multicodec prefix
- didcomm-rust's `VerificationMethodType` has no catch-all deserializer, so an unknown type string fails the **whole** DIDDoc — `toDIDCommDIDDoc` maps anything unrecognized to `Other`
- did:peer:4 resolution keeps references relative per the spec; absolutization happens only in `toDIDCommDIDDoc` (verification methods, relationships, service ids, and `routingKeys`)
- `validateInputDocument` runs on create only, never on resolve: did:peer:4 is self-certifying, so rejecting a counterparty's non-conformant document would cost interoperability for nothing

## Project Structure
```
src/
  schemas/     — TypeBox schemas (did.ts, didcomm.ts)
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
