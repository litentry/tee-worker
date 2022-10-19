import {createTestIdentity, describeLitentry,} from './utils'
import {u8aToHex} from "@polkadot/util";
import {linkIdentity, setUserShieldingKey, unlinkIdentity} from "./indirect_calls";
import {step} from "mocha-steps";
import {assert} from "chai";


describeLitentry('Test Identity', (context) => {
    const aesKey = '0x22fc82db5b606998ad45099b7978b5b4f9dd4ea6017e57370ac56141caaabd12'
    const identity = createTestIdentity()

    step('set user shielding key', async function () {
        const who = await setUserShieldingKey(context, context.defaultSigner, aesKey)
        assert.equal(who, u8aToHex(context.defaultSigner.addressRaw), "check caller error")
    })

    step('link identity', async function () {
        const [challengeCode,] = await linkIdentity(context, context.defaultSigner, aesKey, identity)
        console.log("challengeCode: ", challengeCode)
        assert.isNotEmpty(challengeCode, "challengeCode empty")
    })

    step('unlink identity', async function () {
        const who = await unlinkIdentity(context, context.defaultSigner, aesKey, identity)
        // const msg = generateVerificationMessage(context, hexToU8a(challengeCode), alice.addressRaw, identity)
        assert.equal(who, u8aToHex(context.defaultSigner.addressRaw), "check caller error")
    })
});
