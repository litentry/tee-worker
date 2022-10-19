import WebSocketAsPromised = require("websocket-as-promised");
import WebSocket = require("ws");
import Options = require("websocket-as-promised/types/options");
import {ApiPromise, WsProvider} from "@polkadot/api";
import {GenericEvent, Vec} from "@polkadot/types";
import {
    AESOutput,
    teeTypes,
    IntegrationTestContext,
    PubicKeyJson,
    WorkerRpcReturnString,
    WorkerRpcReturnValue
} from "./type-definitions";
import {cryptoWaitReady} from "@polkadot/util-crypto";
import {KeyringPair} from "@polkadot/keyring/types";
import {Codec} from "@polkadot/types/types";
import {HexString} from "@polkadot/util/types";
import {hexToU8a, u8aToHex} from "@polkadot/util";
import {KeyObject} from "crypto";
import {EventRecord} from "@polkadot/types/interfaces";

const base58 = require('micro-base58');
const crypto = require("crypto");
// in order to handle self-signed certificates we need to turn off the validation
// TODO add self signed certificate ??
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";


export async function sendRequest(wsClient: WebSocketAsPromised, request: any, api: ApiPromise): Promise<WorkerRpcReturnValue> {
    const resp = await wsClient.sendRequest(request, {requestId: 1, timeout: 6000})
    const resp_json = api.createType("WorkerRpcReturnValue", resp.result).toJSON() as WorkerRpcReturnValue
    return resp_json
}

export async function getTEEShieldingKey(wsClient: WebSocketAsPromised, api: ApiPromise): Promise<KeyObject> {
    let request = {jsonrpc: "2.0", method: "author_getShieldingKey", params: [], id: 1};
    let respJSON = await sendRequest(wsClient, request, api)

    const pubKeyHex = api.createType("WorkerRpcReturnString", respJSON.value).toJSON() as WorkerRpcReturnString
    let chunk = Buffer.from(pubKeyHex.vec.slice(2), 'hex');
    let pubKeyJSON = JSON.parse(chunk.toString("utf-8")) as PubicKeyJson

    return crypto.createPublicKey({
        key: {
            "alg": "RSA-OAEP-256",
            "kty": "RSA",
            "use": "enc",
            "n": Buffer.from(pubKeyJSON.n.reverse()).toString('base64url'),
            "e": Buffer.from(pubKeyJSON.e.reverse()).toString('base64url')
        },
        format: 'jwk',
    })
}

export async function initIntegrationTestContext(workerEndpoint: string, substrateEndpoint: string): Promise<IntegrationTestContext> {
    //TODO how to get the shard
    const shard = '0x7cf5d42a86f1bb70d08c1eb687da3a51277383d5e1fa467fb25f017b80834db5'
    // const endpoint = "wss://localhost:2000"
    const wsp = new WebSocketAsPromised(workerEndpoint, <Options>{
        createWebSocket: (url: any) => new WebSocket(url),
        extractMessageData: (event: any) => event, // <- this is important
        packMessage: (data: any) => JSON.stringify(data),
        unpackMessage: (data: string | ArrayBuffer | Blob) => JSON.parse(data.toString()),
        attachRequestId: (data: any, requestId: string | number) => Object.assign({id: requestId}, data), // attach requestId to message as `id` field
        extractRequestId: (data: any) => data && data.id,                                  // read requestId from message `id` field
    })
    await wsp.open()

    const provider = new WsProvider(substrateEndpoint)
    const api = await ApiPromise.create({
        provider, types: teeTypes
    })
    await cryptoWaitReady()


    const teeShieldingKey = await getTEEShieldingKey(wsp, api)
    return <IntegrationTestContext>{
        tee: wsp,
        substrate: api,
        teeShieldingKey,
        shard
    }
}

export async function listenEncryptedEvents(context: IntegrationTestContext, aesKey: HexString, filterObj: { "moduleName": string, "extrinsicName": string, "eventName": string }) {
    return new Promise<{ eventData: HexString[] }>(async (resolve, reject) => {
        let startBlock = 0;
        let timeout = 10; // 10 block number timeout
        const unsubscribe = await context.substrate.rpc.chain.subscribeNewHeads(async (header) => {
            const currentBlockNumber = header.number.toNumber()
            if (startBlock == 0) startBlock = currentBlockNumber;
            if (currentBlockNumber > startBlock + timeout) {
                reject("timeout");
                return
            }
            console.log(`Chain is at block: #${header.number}`);
            const signedBlock = await context.substrate.rpc.chain.getBlock(header.hash);
            const allEvents = await context.substrate.query.system.events.at(header.hash) as Vec<EventRecord>;
            signedBlock.block.extrinsics.forEach((ex, index) => {
                if (!(ex.method.section === filterObj.moduleName && ex.method.method === filterObj.extrinsicName)) {
                    return;
                }
                allEvents
                    .filter(({phase, event}) => {
                        return phase.isApplyExtrinsic && phase.asApplyExtrinsic.eq(index)
                            && event.section == filterObj.moduleName && event.method == filterObj.eventName
                    })
                    .forEach(({event}) => {
                        // const eventData = event.data as AESOutput;
                        const data = event.data as AESOutput[]
                        const eventData: HexString[] = []
                        for (let i = 0; i < data.length; i++) {
                            eventData.push(decryptWithAES(aesKey, data[i]))
                        }
                        resolve({eventData})
                        unsubscribe()
                        return
                    });
            });
        });
    });
}


// export function encryptWithAES(key: HexString, plaintext: HexString): [Buffer, Buffer, Buffer] {
//     console.log("plaintext: ", plaintext)
//     const iv = new Buffer(crypto.randomBytes(12), 'utf8');
//     const secretKey = crypto.createSecretKey(hexToU8a(key))
//     console.log(secretKey)
//     const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
//     cipher.setAAD(Buffer.from('', 'hex'))
//     let enc1 = cipher.update(hexToU8a(plaintext));
//     let enc2 = cipher.final();
//     console.log('111', enc1.toString('hex'), enc2.toString('hex'))
//
//     const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, iv);
//     decipher.setAuthTag(cipher.getAuthTag())
//     console.log(decipher.update(enc1).toString('hex'))
//     console.log(decipher.final().toString('hex'))
//     console.log(`0x${iv.toString('hex')}`)
//     return [Buffer.concat([enc1, enc2]), iv, cipher.getAuthTag()];
// }

export function decryptWithAES(key: HexString, aesOutput: AESOutput): HexString {
    const secretKey = crypto.createSecretKey(hexToU8a(key))
    const tagSize = 16
    const ciphertext = aesOutput.ciphertext ? aesOutput.ciphertext : hexToU8a("0x")
    const initialization_vector = aesOutput.nonce ? aesOutput.nonce : hexToU8a("0x")
    const aad = aesOutput.aad ? aesOutput.aad : hexToU8a("0x")

    // notice!!! extract author_tag from ciphertext
    // maybe this code only works with rust aes encryption
    const authorTag = ciphertext.subarray(ciphertext.length - tagSize)
    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, initialization_vector);
    decipher.setAAD(aad);
    decipher.setAuthTag(authorTag)

    let part1 = decipher.update(ciphertext.subarray(0, ciphertext.length - tagSize), undefined, 'hex');
    let part2 = decipher.final('hex')
    return `0x${part1 + part2}`;
}


export async function createTrustedCallSigned(api: ApiPromise, trustedCall: [string, string], account: KeyringPair, mrenclave: string, shard: string, nonce: Codec, params: Array<any>) {
    const [variant, argType] = trustedCall;
    const call = api.createType('TrustedCall', {
        [variant]: api.createType(argType, params)
    });
    const payload = Uint8Array.from([...call.toU8a(), ...nonce.toU8a(), ...base58.decode(mrenclave), ...hexToU8a(shard)]);
    const signature = api.createType('MultiSignature', {
        "Sr25519": u8aToHex(account.sign(payload))
    })
    return api.createType('TrustedCallSigned', {
        call: call,
        index: nonce,
        signature: signature
    });
}

export function encryptWithTeeShieldingKey(teeShieldingKey: KeyObject, plaintext: HexString): Buffer {
    return crypto.publicEncrypt({
        key: teeShieldingKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, hexToU8a(plaintext))
}
