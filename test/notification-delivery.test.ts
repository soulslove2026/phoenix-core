import test from "node:test";
import assert from "node:assert/strict";
import { NotificationDeliveryService } from "../src/identity/notification-delivery.js";
import type { PhaseBIdentityRepository } from "../src/identity/phase-b-repository.js";
import { encryptNotificationPayload } from "../src/identity/token-crypto.js";

const key=Buffer.alloc(32,9).toString("base64url");

test("notification worker decrypts, sends idempotently, and acknowledges",async()=>{
  const encrypted=encryptNotificationPayload({kind:"security_notice",recipient:"u@example.com",event:"passkey_added"},key);
  let sent=false;let delivered:any;
  const repository={
    async claimNotifications(){return[{id:"00000000-0000-4000-8000-000000000001",userId:"00000000-0000-4000-8000-000000000002",kind:"security_notice",...encrypted,attempts:1,lockToken:"lock"}];},
    async markNotificationSent(){sent=true;},async markNotificationFailed(){throw new Error("unexpected");}
  } as unknown as PhaseBIdentityRepository;
  const service=new NotificationDeliveryService({repository,provider:{async deliver(input){delivered=input;}},notificationKey:key,from:"security@example.com",batchSize:10,maxAttempts:3});
  assert.deepEqual(await service.runBatch(),{claimed:1,sent:1,failed:0});
  assert.equal(sent,true);assert.equal(delivered.to,"u@example.com");assert.equal(delivered.template,"phoenix.identity.security_notice");assert.equal(delivered.idempotencyKey,"00000000-0000-4000-8000-000000000001");
});
