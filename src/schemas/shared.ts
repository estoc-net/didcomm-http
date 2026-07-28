import { Type, type Static, type TSchema } from "@sinclair/typebox";

/**
 * Every schema `shared()` has named, in the order they were declared. Fastify
 * holds them by `$id` (`server.ts` registers the lot before any route), which
 * is what lets a `$ref` resolve for validation and for serialization.
 */
export const sharedSchemas: TSchema[] = [];

/**
 * Names a schema in the document, and returns the reference that every use of
 * it goes through — so a shape used by four operations is written once and
 * lands in `components/schemas` once, rather than being copied out under each
 * of them.
 *
 * A generated client is where that shows: a copy per operation gives a type per
 * operation, so the DIDComm message packed encrypted and the one packed signed
 * are two unrelated types and no caller can build one message and pack it both
 * ways. Naming the schema here is what makes them the same type there.
 *
 * `Type.Unsafe` carries the static type across the reference, which is the
 * spelling TypeBox 0.34 asks for — `Type.Ref` alone resolves to `unknown`, and
 * the routes infer their bodies from these.
 */
export function shared<T extends TSchema>($id: string, schema: T) {
  sharedSchemas.push({ ...schema, $id });

  return Type.Unsafe<Static<T>>(Type.Ref($id));
}
