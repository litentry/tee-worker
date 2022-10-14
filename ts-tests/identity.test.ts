import {connectWorker, getTEEShieldingKey, initSubstrateAPI, setUserShieldingKey} from './utils'
import {Keyring} from "@polkadot/api";
import {KeyringPair} from "@polkadot/keyring/types";

const keyring = new Keyring({type: 'sr25519'});

(async () => {
    const worker = await connectWorker("wss://localhost:2000")
    const substrateAPI = await initSubstrateAPI('ws://integritee-node:9912')
    const teeShieldingKey = await getTEEShieldingKey(worker, substrateAPI)
    const alice: KeyringPair = keyring.addFromUri('//Alice', {name: 'Alice'})
    await setUserShieldingKey(worker, substrateAPI, alice, teeShieldingKey, '0x00629874b38f161040b4012f7bf33e66771e78c0544fa98139485b9c5b32734f', '0x22fc82db5b606998ad45099b7978b5b4f9dd4ea6017e57370ac56141caaabd12')
    console.log(teeShieldingKey)
    process.exit(0)
})()
