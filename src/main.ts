import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";

async function main(): Promise<void> {
  const config=loadConfig();
  const app=await buildApp(config);
  const shutdown=async (signal:string) => { app.log.info({signal},"shutdown.requested"); await app.close(); };
  process.once("SIGTERM",()=>void shutdown("SIGTERM"));
  process.once("SIGINT",()=>void shutdown("SIGINT"));
  await app.listen({host:config.host,port:config.port});
}
main().catch(error=>{ console.error(JSON.stringify({level:"error",event:"service.failed",message:error instanceof Error?error.message:"unknown"})); process.exitCode=1; });
