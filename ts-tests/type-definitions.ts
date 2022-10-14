export const definitions = {
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
}
