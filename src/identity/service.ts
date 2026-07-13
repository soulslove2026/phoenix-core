import { randomUUID } from "node:crypto";
import { normalizeAndValidateEmail, EmailValidationError } from "./email.js";
import { passwordHasher, type PasswordHasher } from "./password.js";
import { createOpaqueToken, encryptNotificationPayload, hashOpaqueToken } from "./token-crypto.js";
import { IdentityRepositoryConflictError, type IdentityRepository, type SessionCreateInput } from "./repository.js";
import type { PublicSession, PublicUser, SecurityContext, SessionRecord, UserRecord } from "./types.js";

export class IdentityError extends Error { constructor(public readonly code:string,public readonly statusCode:number){super(code);} }

type Options = Readonly<{
  sessionAbsoluteTtlSeconds:number; sessionIdleTtlSeconds:number; verificationTtlSeconds:number; passwordResetTtlSeconds:number;
  tokenPepper:string; notificationKey:string; passwords?:PasswordHasher;
}>;

export class IdentityService {
  private readonly passwords:PasswordHasher;
  constructor(private readonly repository:IdentityRepository,private readonly options:Options){
    this.passwords=options.passwords??passwordHasher;
    if(options.sessionIdleTtlSeconds>options.sessionAbsoluteTtlSeconds)throw new Error("idle TTL exceeds absolute TTL");
  }

  async register(input:{email:string;displayName:string;password:string},context:SecurityContext):Promise<void>{
    let email:string;
    try{email=normalizeAndValidateEmail(input.email);}catch(error){if(error instanceof EmailValidationError)throw new IdentityError("registration_invalid",400);throw error;}
    const displayName=input.displayName.trim(); if(displayName.length<2||displayName.length>80)throw new IdentityError("registration_invalid",400);
    let passwordHash:string; try{passwordHash=await this.passwords.hash(input.password,{email,displayName});}catch{throw new IdentityError("registration_invalid",400);}
    let user=await this.repository.findUserByEmail(email);
    if(!user){ try{user=await this.repository.createUser({id:randomUUID(),email,displayName,passwordHash});}catch(error){if(error instanceof IdentityRepositoryConflictError)user=await this.repository.findUserByEmail(email);else throw error;} }
    if(user&&!user.emailVerifiedAt&&user.status==="active")await this.issueAction(user,"verify_email",this.options.verificationTtlSeconds,"email_verification");
    await this.event("identity.registration_requested","accepted",context,user?.id,email);
  }

  async requestEmailVerification(emailInput:string,context:SecurityContext):Promise<void>{
    const email=this.safeEmail(emailInput); const user=email?await this.repository.findUserByEmail(email):null;
    if(user&&!user.emailVerifiedAt&&user.status==="active")await this.issueAction(user,"verify_email",this.options.verificationTtlSeconds,"email_verification");
    await this.event("identity.email_verification_requested","accepted",context,user?.id,email??emailInput);
  }

  async confirmEmailVerification(token:string,context:SecurityContext):Promise<{user:PublicUser;sessionToken:string}>{
    const user=await this.repository.verifyEmailWithToken(hashOpaqueToken(token,this.options.tokenPepper));
    if(!user||user.status!=="active")throw new IdentityError("verification_token_invalid",400);
    const session=await this.issueSession(user,context);
    await this.event("identity.email_verified","success",context,user.id);
    return {user:toPublicUser(user),sessionToken:session.token};
  }

  async login(input:{email:string;password:string},context:SecurityContext):Promise<{user:PublicUser;sessionToken:string}>{
    const email=this.safeEmail(input.email); const user=email?await this.repository.findUserByEmail(email):null;
    const verification=user?await this.passwords.verify(input.password,user.passwordHash):await this.passwords.verify(input.password,DUMMY_HASH);
    if(!user||user.status!=="active"||!verification.valid){await this.event("identity.login","denied",context,user?.id,email??input.email);throw new IdentityError("credentials_invalid",401);}
    if(!user.emailVerifiedAt){await this.event("identity.login_unverified","denied",context,user.id,user.email);throw new IdentityError("email_verification_required",403);}
    if(verification.needsRehash){const upgraded=await this.passwords.hash(input.password,{email:user.email,displayName:user.displayName});await this.repository.upgradePasswordHash(user.id,upgraded);}
    const session=await this.issueSession(user,context); await this.event("identity.login","success",context,user.id);
    return {user:toPublicUser(user),sessionToken:session.token};
  }

  async requestPasswordReset(emailInput:string,context:SecurityContext):Promise<void>{
    const email=this.safeEmail(emailInput); const user=email?await this.repository.findUserByEmail(email):null;
    if(user&&user.status==="active"&&user.emailVerifiedAt)await this.issueAction(user,"password_reset",this.options.passwordResetTtlSeconds,"password_reset");
    await this.event("identity.password_reset_requested","accepted",context,user?.id,email??emailInput);
  }

  async confirmPasswordReset(input:{token:string;newPassword:string},context:SecurityContext):Promise<void>{
    let passwordHash:string; try{passwordHash=await this.passwords.hash(input.newPassword);}catch{throw new IdentityError("password_invalid",400);}
    const userId=await this.repository.resetPasswordWithToken(hashOpaqueToken(input.token,this.options.tokenPepper),passwordHash);
    if(!userId)throw new IdentityError("reset_token_invalid",400);
    await this.event("identity.password_reset_completed","success",context,userId);
  }

  async authenticate(token:string):Promise<{user:PublicUser;session:SessionRecord}>{
    const session=await this.repository.findActiveSessionByTokenHash(hashOpaqueToken(token,this.options.tokenPepper));
    if(!session)throw new IdentityError("session_invalid",401);
    const user=await this.repository.findUserById(session.userId);
    if(!user||user.status!=="active"||!user.emailVerifiedAt||user.authVersion!==session.authVersion)throw new IdentityError("session_invalid",401);
    const idleExpiry=new Date(Math.min(Date.now()+this.options.sessionIdleTtlSeconds*1000,new Date(session.expiresAt).getTime())).toISOString();
    await this.repository.touchSession(session.id,idleExpiry);
    return {user:toPublicUser(user),session};
  }

  async rotateSession(token:string,context:SecurityContext):Promise<string>{
    const authenticated=await this.authenticate(token); const nextToken=createOpaqueToken("phx_s"); const now=Date.now();
    if(new Date(authenticated.session.expiresAt).getTime()<=now+5_000)throw new IdentityError("session_invalid",401);
    const base=this.sessionInput(authenticated.user.id,authenticated.session.authVersion,nextToken,context,now,authenticated.session.id);
    const input:SessionCreateInput={...base,expiresAt:authenticated.session.expiresAt,idleExpiresAt:new Date(Math.min(now+this.options.sessionIdleTtlSeconds*1000,new Date(authenticated.session.expiresAt).getTime())).toISOString()};
    const rotated=await this.repository.rotateSession(hashOpaqueToken(token,this.options.tokenPepper),input);
    if(!rotated)throw new IdentityError("session_invalid",401);
    await this.event("identity.session_rotated","success",context,authenticated.user.id);
    return nextToken;
  }

  async listSessions(token:string):Promise<PublicSession[]>{const auth=await this.authenticate(token);const sessions=await this.repository.listActiveSessions(auth.user.id);return sessions.map(s=>toPublicSession(s,s.id===auth.session.id));}
  async revokeSessionById(token:string,sessionId:string,context:SecurityContext):Promise<void>{const auth=await this.authenticate(token);await this.repository.revokeSessionById(auth.user.id,sessionId);await this.event("identity.session_revoked","success",context,auth.user.id);}
  async logout(token:string,context:SecurityContext):Promise<void>{const hash=hashOpaqueToken(token,this.options.tokenPepper);const session=await this.repository.findActiveSessionByTokenHash(hash);await this.repository.revokeSession(hash);if(session)await this.event("identity.logout","success",context,session.userId);}
  async logoutAll(token:string,context:SecurityContext):Promise<void>{const auth=await this.authenticate(token);await this.repository.revokeAllSessions(auth.user.id);await this.event("identity.logout_all","success",context,auth.user.id);}

  private safeEmail(value:string):string|null{try{return normalizeAndValidateEmail(value);}catch{return null;}}
  private async issueAction(user:UserRecord,purpose:"verify_email"|"password_reset",ttlSeconds:number,kind:"email_verification"|"password_reset"):Promise<void>{
    const token=createOpaqueToken(purpose==="verify_email"?"phx_v":"phx_r"); const expiresAt=new Date(Date.now()+ttlSeconds*1000).toISOString();
    const encrypted=encryptNotificationPayload({kind,recipient:user.email,token,expiresAt},this.options.notificationKey);
    await this.repository.issueActionToken({id:randomUUID(),userId:user.id,purpose,tokenHash:hashOpaqueToken(token,this.options.tokenPepper),expiresAt,notification:{id:randomUUID(),kind,...encrypted}});
  }
  private async issueSession(user:UserRecord,context:SecurityContext):Promise<{token:string;record:SessionRecord}>{const token=createOpaqueToken("phx_s");const now=Date.now();const record=await this.repository.createSession(this.sessionInput(user.id,user.authVersion,token,context,now));return{token,record};}
  private sessionInput(userId:string,authVersion:number,token:string,context:SecurityContext,now:number,rotatedFromSessionId?:string):SessionCreateInput{return{id:randomUUID(),userId,tokenHash:hashOpaqueToken(token,this.options.tokenPepper),authVersion,userAgentHash:context.userAgentHash,ipHash:context.ipHash,idleExpiresAt:new Date(now+this.options.sessionIdleTtlSeconds*1000).toISOString(),expiresAt:new Date(now+this.options.sessionAbsoluteTtlSeconds*1000).toISOString(),...(rotatedFromSessionId?{rotatedFromSessionId}:{})};}
  private async event(eventType:string,outcome:"success"|"denied"|"accepted",context:SecurityContext,userId?:string,subject?:string){const subjectHash=subject?hashOpaqueToken(`subject:${subject.toLowerCase()}`,this.options.tokenPepper):undefined;await this.repository.recordSecurityEvent({id:randomUUID(),...(userId?{userId}:{}),eventType,outcome,...(subjectHash?{subjectHash}:{}),metadata:{ipHash:context.ipHash,userAgentHash:context.userAgentHash}});}
}

// Valid scrypt legacy hash used only to reduce missing-account timing differences.
const DUMMY_HASH="scrypt$v2$131072$8$1$cGhvZW5peC1kdW1teS1zYWx0$mvGDHRcN-MxKy8iKcSTDJ3dxl5enp_Aof3FDnhrrTDuNiGySukWU4iMO78beo6g6aT1nKUSDvKHcDnEpSQhcvA";
function toPublicUser(user:UserRecord):PublicUser{return{id:user.id,email:user.email,displayName:user.displayName,status:user.status,emailVerified:Boolean(user.emailVerifiedAt),createdAt:user.createdAt};}
function toPublicSession(session:SessionRecord,current:boolean):PublicSession{return{id:session.id,current,createdAt:session.createdAt,lastSeenAt:session.lastSeenAt,idleExpiresAt:session.idleExpiresAt,expiresAt:session.expiresAt};}
