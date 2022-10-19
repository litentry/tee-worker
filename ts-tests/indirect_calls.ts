import {AESOutput, IntegrationTestContext, LitentryIdentity} from "./type-definitions";
import {decryptWithAES, encryptWithTeeShieldingKey, listenEncryptedEvents} from "./utils";
import {KeyringPair} from "@polkadot/keyring/types";
import {HexString} from "@polkadot/util/types";
import {u8aToHex} from "@polkadot/util";

export async function setUserShieldingKey(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString) {
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, aesKey).toString('hex')
    await context.substrate.tx.identityManagement.setUserShieldingKey(context.shard, `0x${ciphertext}`).signAndSend(signer)
    const event = await listenEncryptedEvents(context, aesKey, {
        moduleName: "identityManagement",
        extrinsicName: "userShieldingKeySet",
        eventName: "UserShieldingKeySet"
    })
    const [who] = event.eventData;
    if (who == u8aToHex(signer.addressRaw)) {
        console.log("set user shielding key success...")
    }
}

export async function linkIdentity(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString, identity: LitentryIdentity) {
    const encode = context.substrate.createType("LitentryIdentity", identity).toHex()
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, encode).toString('hex')
    await context.substrate.tx.identityManagement.linkIdentity(context.shard, `0x${ciphertext}`, null).signAndSend(signer)
    const event = await listenEncryptedEvents(context, aesKey, {
        moduleName: "identityManagement",
        extrinsicName: "challengeCodeGenerated",
        eventName: "ChallengeCodeGenerated"
    })
    const [_who, _identity, challengeCode] = event.eventData;
    console.log("challengeCode: ", challengeCode)
}

export async function unlinkIdentity(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString, identity: LitentryIdentity) {
    const encode = context.substrate.createType("LitentryIdentity", identity).toHex()
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, encode).toString('hex')
    await context.substrate.tx.identityManagement.unlinkIdentity(context.shard, `0x${ciphertext}`).signAndSend(signer)
    const event = await listenEncryptedEvents(context, aesKey, {
        moduleName: "identityManagement",
        extrinsicName: "identityUnlinked",
        eventName: "IdentityUnlinked"
    })
    const [who, _identity] = event.eventData;
    if (who == u8aToHex(signer.addressRaw)) {
        console.log("unlink identity successful. identity:", identity)
    }
}

export async function verifyIdentity(context: IntegrationTestContext, signer: KeyringPair, aesKey: HexString, identity: LitentryIdentity) {
    const encode = context.substrate.createType("LitentryIdentity", identity).toHex()
    const ciphertext = encryptWithTeeShieldingKey(context.teeShieldingKey, encode).toString('hex')
    await context.substrate.tx.identityManagement.unlinkIdentity(context.shard, `0x${ciphertext}`).signAndSend(signer)
}
