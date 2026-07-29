import { buildServer } from "./server.js";

const HOST = process.env.HOST ?? "0.0.0.0";
const PORT = parseInt(process.env.PORT ?? "3000", 10);

async function main() {
  const server = await buildServer({
    allowPrivateDelivery: process.env.ALLOW_PRIVATE_DELIVERY === "true",
  });

  await server.listen({ host: HOST, port: PORT });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
