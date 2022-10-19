import {IntegrationTestContext, LitentryIdentity} from "./type-definitions";
import {encryptWithTeeShieldingKey, listenEncryptedEvents} from "./utils";
import {KeyringPair} from "@polkadot/keyring/types";
import {HexString} from "@polkadot/util/types";

export async function setUserShieldingKey(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString): Promise<HexString> {
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, aesKey).toString('hex')
    await context.substrate.tx.identityManagement.setUserShieldingKey(context.shard, `0x${ciphertext}`).signAndSend(signer)
    const event = await listenEncryptedEvents(context, aesKey, {
        moduleName: "identityManagement",
        extrinsicName: "userShieldingKeySet",
        eventName: "UserShieldingKeySet"
    })
    const [who] = event.eventData;
    return who

}

export async function linkIdentity(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString, identity: LitentryIdentity): Promise<HexString[]> {
    const encode = context.substrate.createType("LitentryIdentity", identity).toHex()
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, encode).toString('hex')
    await context.substrate.tx.identityManagement.linkIdentity(context.shard, `0x${ciphertext}`, null).signAndSend(signer)
    const event = await listenEncryptedEvents(context, aesKey, {
        moduleName: "identityManagement",
        extrinsicName: "challengeCodeGenerated",
        eventName: "ChallengeCodeGenerated"
    })
    const [who, _identity, challengeCode] = event.eventData;
    return [who, challengeCode]
}

export async function unlinkIdentity(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString, identity: LitentryIdentity): Promise<HexString> {
    const encode = context.substrate.createType("LitentryIdentity", identity).toHex()
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, encode).toString('hex')
    await context.substrate.tx.identityManagement.unlinkIdentity(context.shard, `0x${ciphertext}`).signAndSend(signer)
    const event = await listenEncryptedEvents(context, aesKey, {
        moduleName: "identityManagement",
        extrinsicName: "identityUnlinked",
        eventName: "IdentityUnlinked"
    })
    const [who, _identity] = event.eventData;
    return who
}

export async function verifyIdentity(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString, identity: LitentryIdentity) {
    const encode = context.substrate.createType("LitentryIdentity", identity).toHex()
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, encode).toString('hex')
    await context.substrate.tx.identityManagement.unlinkIdentity(context.shard, `0x${ciphertext}`).signAndSend(signer)
}
