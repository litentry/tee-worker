import {encryptWithTeeShieldingKey, initIntegrationTestContext,} from './utils'
import {Keyring} from "@polkadot/api";
import {KeyringPair} from "@polkadot/keyring/types";
import type {IntegrationTestContext, LitentryIdentity} from "./type-definitions";
import {u8aToHex} from "@polkadot/util";
import {linkIdentity, setUserShieldingKey} from "./indirect_calls";

const keyring = new Keyring({type: 'sr25519'});


(async () => {
    const aesKey = '0x22fc82db5b606998ad45099b7978b5b4f9dd4ea6017e57370ac56141caaabd12'
    const context = await initIntegrationTestContext("wss://localhost:2000", "ws://integritee-node:9912")

    const alice: KeyringPair = keyring.addFromUri('//Alice', {name: 'Alice'})
    const identity = createTestIdentity()

    await setUserShieldingKey(context, alice, aesKey)
    await linkIdentity(context, alice, aesKey, identity)
    // await unlinkIdentity(context, alice, aesKey, identity)

    // await verifyIdentity(context, alice, identity)
    const challengeCode: Uint8Array = Uint8Array.from([210, 27, 119, 197, 149, 193, 144, 29, 237, 192, 119, 215, 39, 17, 68, 233])
    const msg = generateVerificationMessage(context, challengeCode, alice.addressRaw, identity)
    console.log(u8aToHex(msg))
    // await tt()
    // await postTweet(u8aToHex(msg))
    // await test();
})()

//<challeng-code> + <litentry-AccountId32> + <Identity>
function generateVerificationMessage(context: IntegrationTestContext, challengeCode: Uint8Array, signerAddress: Uint8Array, identity: LitentryIdentity): Buffer {
    // const code = hexToU8a(challengeCode);
    const encode = context.substrate.createType("LitentryIdentity", identity).toU8a()
    const msg = Buffer.concat([challengeCode, signerAddress, encode])
    return encryptWithTeeShieldingKey(context.teeShieldingKey, `0x${msg.toString('hex')}`)
}

function createTestIdentity(): LitentryIdentity {
    return <LitentryIdentity>{
        handle: {
            PlainString: `0x${Buffer.from('litentry', 'utf8').toString("hex")}`
        },
        web_type: {
            Web2: "Twitter"
        }
    }
}
