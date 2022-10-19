import {ApiPromise} from "@polkadot/api";
import {KeyObject} from "crypto";
import {HexString} from "@polkadot/util/types";
import WebSocketAsPromised = require("websocket-as-promised");

export const teeTypes = {
    WorkerRpcReturnString: {
        vec: "Bytes"
    },
    WorkerRpcReturnValue: {
        value: 'Bytes',
        do_watch: 'bool',
        status: 'DirectRequestStatus',
    },
    TrustedOperation: {
        _enum: {
            indirect_call: "(TrustedCallSigned)",
            direct_call: "(TrustedCallSigned)",
            get: "(Getter)",
        }
    },
    TrustedCallSigned: {
        call: 'TrustedCall',
        index: 'u32',
        signature: 'MultiSignature',
    },
    Getter: {
        _enum: {
            'public': '(PublicGetter)',
            'trusted': '(TrustedGetterSigned)'
        }
    },
    PublicGetter: {
        _enum: [
            'some_value'
        ]
    },
    TrustedGetterSigned: {
        getter: "TrustedGetter",
        signature: "MultiSignature"
    },

    /// important
    TrustedGetter: {
        _enum: {
            free_balance: '(AccountId)'
        }
    },
    /// important
    TrustedCall: {
        _enum: {
            balance_set_balance: '(AccountId, AccountId, Balance, Balance)',
            balance_transfer: '(AccountId, AccountId, Balance)',
            balance_unshield: '(AccountId, AccountId, Balance, ShardIdentifier)',
        }
    },
    DirectRequestStatus: {
        _enum: [
            //TODO support TrustedOperationStatus(TrustedOperationStatus)
            'Ok', 'TrustedOperationStatus', 'Error'
        ]
    },

    /// identity
    LitentryIdentity: {
        web_type: "IdentityWebType",
        handle: "IdentityHandle"
    },
    IdentityWebType: {
        _enum: {
            Web2: "Web2Network",
            Web3: "Web3Network"
        }
    },
    Web2Network: {
        _enum: ["Twitter", "Discord", "Github"]
    },
    Web3Network: {
        _enum: {
            Substrate: "SubstrateNetwork",
            Evm: "EvmNetwork"
        }
    },
    SubstrateNetwork: {
        _enum: ["Polkadot", "Kusama", "Litentry", "Litmus"]
    },
    EvmNetwork: {
        _enum: ['Ethereum', 'BSC']
    },
    IdentityHandle: {
        _enum: {
            Address32: '[u8;32]',
            Address20: '[u8;20]',
            PlainString: 'Vec<u8>'
        }
    }
}

export type WorkerRpcReturnValue = {
    value: HexString
    do_watch: boolean
    status: string
}

export type WorkerRpcReturnString = {
    vec: string
}

export type PubicKeyJson = {
    n: Uint8Array,
    e: Uint8Array
}


export type IntegrationTestContext = {
    tee: WebSocketAsPromised,
    substrate: ApiPromise,
    teeShieldingKey: KeyObject,
    shard: HexString
}

export class AESOutput {
    ciphertext?: Uint8Array
    aad?: Uint8Array
    nonce?: Uint8Array
}

export type LitentryIdentity = {
    web_type: IdentityWebType,
    handle: IdentityHandle,
}

export type IdentityWebType = {
    Web2?: Web2Network
    Web3?: Web3Network
}

export type IdentityHandle = {
    Address32: `0x${string}`,
    Address20: `0x${string},`
    PlainString: `0x${string}`
}

export type Web3Network = {
    Substrate: SubstrateNetwork
    Evm: EvmNetwork
}

export type Web2Network = "Twitter" | "Discord" | "Github"
export type SubstrateNetwork = "Polkadot" | "Kusama" | "Litentry" | "Litmus"
export type EvmNetwork = 'Ethereum' | 'BSC'

