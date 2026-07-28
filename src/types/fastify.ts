import type { FastifyInstance, FastifyTypeProvider } from "fastify";
import type { Static, TSchema } from "@sinclair/typebox";

type Resolve<Schema> = Schema extends TSchema ? Static<Schema> : unknown;

/**
 * What `@fastify/type-provider-typebox` provides, with the conditional moved
 * behind a named alias.
 *
 * Its own spelling inlines it —
 * `this['schema'] extends TSchema ? Static<this['schema']> : unknown` — and a
 * `Type.Ref` does not survive that: resolved against the still-deferred
 * `this['schema']`, every referenced property reaches the handler as `unknown`,
 * while `Static` applied to the same schema outside a route infers it exactly.
 * Passing the deferred type through `Resolve` is the whole of the difference.
 *
 * It matters because every shared schema is used through a reference, so
 * without this a handler's `request.body.message` is `unknown` and the service
 * it is handed to no longer typechecks against what the route validated.
 */
export interface TypeBoxProvider extends FastifyTypeProvider {
  validator: Resolve<this["schema"]>;
  serializer: Resolve<this["schema"]>;
}

export type TypedFastify = FastifyInstance<any, any, any, any, TypeBoxProvider>;
