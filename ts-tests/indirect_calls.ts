import {IntegrationTestContext, LitentryIdentity, LitentryValidationData} from "./type-definitions";
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

export async function verifyIdentity(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString, identity: LitentryIdentity, data: LitentryValidationData) {
    const identity_encode = context.substrate.createType("LitentryIdentity", identity).toHex()
    const validation_encode = context.substrate.createType("LitentryValidationData", data).toHex()
    const identity_ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, identity_encode).toString('hex')
    const validation_ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, validation_encode).toString('hex')
    await context.substrate.tx.identityManagement.verifyIdentity(context.shard, `0x${identity_ciphertext}`, `0x${validation_ciphertext}`).signAndSend(signer)
    const event = await listenEncryptedEvents(context, aesKey, {
        moduleName: "identityManagement",
        extrinsicName: "identityVerified",
        eventName: "IdentityVerified"
    })
    const [who, _identity] = event.eventData;
    return who
}
