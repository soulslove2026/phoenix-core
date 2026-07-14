import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  type Uint8Array_
} from "@simplewebauthn/server";
import type { PasskeyRecord } from "./phase-b-types.js";
import type { UserRecord } from "./types.js";

function uuidBytes(uuid: string): Uint8Array_ {
  const hex = uuid.replaceAll("-", "");
  if (!/^[a-f0-9]{32}$/iu.test(hex)) throw new Error("webauthn_user_id_invalid");
  return Uint8Array.from(Buffer.from(hex, "hex")) as Uint8Array_;
}

export class PasskeyManager {
  constructor(private readonly config: Readonly<{
    rpName: string;
    rpId: string;
    origins: string[];
    timeoutMs: number;
  }>) {}

  async registrationOptions(user: UserRecord, passkeys: PasskeyRecord[]): Promise<PublicKeyCredentialCreationOptionsJSON> {
    return generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userID: uuidBytes(user.id),
      userName: user.email,
      userDisplayName: user.displayName,
      timeout: this.config.timeoutMs,
      attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      excludeCredentials: passkeys.map((passkey) => ({ id: passkey.credentialId, transports: passkey.transports })),
      supportedAlgorithmIDs: [-7, -257, -8]
    });
  }

  async verifyRegistration(response: RegistrationResponseJSON, expectedChallenge: string) {
    return verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.config.origins,
      expectedRPID: this.config.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -257, -8]
    });
  }

  async authenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    return generateAuthenticationOptions({
      rpID: this.config.rpId,
      timeout: this.config.timeoutMs,
      userVerification: "required"
    });
  }

  async verifyAuthentication(response: AuthenticationResponseJSON, expectedChallenge: string, passkey: PasskeyRecord) {
    return verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.config.origins,
      expectedRPID: this.config.rpId,
      requireUserVerification: true,
      credential: {
        id: passkey.credentialId,
        publicKey: Uint8Array.from(passkey.publicKey) as Uint8Array_,
        counter: passkey.counter,
        transports: passkey.transports
      }
    });
  }
}
