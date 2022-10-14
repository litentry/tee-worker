import WebSocketAsPromised = require("websocket-as-promised");
import WebSocket = require("ws");
import {ApiPromise, WsProvider} from "@polkadot/api";
import {TypeRegistry} from "@polkadot/types";
import {definitions} from "./type-definitions";
import {cryptoWaitReady} from "@polkadot/util-crypto";
import Options = require("websocket-as-promised/types/options");
import {KeyringPair} from "@polkadot/keyring/types";
import {Codec} from "@polkadot/types/types";
import {hexToU8a, u8aToHex} from "@polkadot/util";
import {KeyObject} from "crypto";

const base58 = require('micro-base58');
const crypto = require("crypto");
// in order to handle self-signed certificates we need to turn off the validation
// TODO add self signed certificate ??
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

type WorkerRpcReturnValue = {
    value: `0x${string}`
    do_watch: boolean
    status: string
}

type WorkerRpcReturnString = {
    vec: string
}

type PubicKeyJson = {
    n: Uint8Array,
    e: Uint8Array
}

// class DefaultWSOptions implements Options {
// 	createWebSocket: (url: string) => {
// 		// re
// 	};
// }

export async function connectWorker(endpoint: string): Promise<WebSocketAsPromised> {
    // const endpoint = "wss://localhost:2000"
    const wsp = new WebSocketAsPromised(endpoint, {
        createWebSocket: (url: any) => new WebSocket(url),
        extractMessageData: (event: any) => event, // <- this is important
        packMessage: (data: any) => JSON.stringify(data),
        unpackMessage: (data: string | ArrayBuffer | Blob) => JSON.parse(data.toString()),
        attachRequestId: (data: any, requestId: string | number) => Object.assign({id: requestId}, data), // attach requestId to message as `id` field
        extractRequestId: (data: any) => data && data.id,                                  // read requestId from message `id` field
    })
    await wsp.open()
    return wsp
}


export async function initSubstrateAPI(endpoint: string): Promise<ApiPromise> {
    // const endpoint = 'ws://integritee-node:9912'
    // const registry = new TypeRegistry()

    const provider = new WsProvider(endpoint)
    const api = await ApiPromise.create({
        provider, types: definitions
    })
    await cryptoWaitReady()
    return api;
}

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
    pubKeyJSON.n = pubKeyJSON.n.reverse()

    return crypto.createPublicKey({
        key: {
            "alg": "RSA-OAEP-256",
            "kty": "RSA",
            "use": "enc",
            "n": Buffer.from(pubKeyJSON.n).toString('base64url'),
            "e": Buffer.from(pubKeyJSON.e).toString('base64url')
        },
        format: 'jwk',
    })
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

export async function setUserShieldingKey(wsClient: WebSocketAsPromised, api: ApiPromise, signer: KeyringPair, teeShieldingKey: KeyObject, shard: string, aesKey: `0x${string}`) {

    const encrypted_key = crypto.publicEncrypt({
        key: teeShieldingKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, hexToU8a(aesKey))

    await api.tx.identityManagement.setUserShieldingKey({
        shard: shard,
        encrypted_key: encrypted_key.toString('hex')
    }).signAndSend(signer)
}
