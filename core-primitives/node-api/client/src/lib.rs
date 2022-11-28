mod message_handler;

use crate::message_handler::{
	on_extrinsic_msg_submit_only, on_extrinsic_msg_until_broadcast,
	on_extrinsic_msg_until_finalized, on_extrinsic_msg_until_in_block,
	on_extrinsic_msg_until_ready, on_get_request_msg, on_subscription_msg, read_until_text_message,
	OnMessageFn,
};
use log::{debug, error, info, warn};
use serde_json::Value;
use sp_core::H256 as Hash;
use std::{
	net::TcpStream,
	string::{String, ToString},
	sync::mpsc::Sender as ThreadOut,
	thread,
	thread::sleep,
	time::Duration,
};
pub use substrate_api_client::{
	std::{
		rpc::{json_req, ws_client::Subscriber},
		FromHexString, RpcClient as RpcClientTrait,
	},
	ApiClientError, ApiResult, XtStatus,
};
use tungstenite::{
	client::connect_with_config,
	protocol::{frame::coding::CloseCode, CloseFrame},
	stream::MaybeTlsStream,
	Message, WebSocket,
};
use url::Url;
use ws::{self, ErrorKind};

type MySocket = WebSocket<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Clone)]
pub struct LitentryWsRpcClient {
	url: String,
	max_attempts: u8,
}

impl LitentryWsRpcClient {
	pub fn new(url: &str, max_attempts: u8) -> LitentryWsRpcClient {
		LitentryWsRpcClient { url: url.to_string(), max_attempts }
	}

	fn direct_rpc_request(
		&self,
		json_req: String,
		on_message_fn: OnMessageFn,
	) -> ApiResult<String> {
		let url = Url::parse(self.url.as_str()).map_err(|e| ApiClientError::Other(e.into()))?;
		let mut current_attempt: u8 = 1;
		let mut socket: MySocket;

		let send_request =
			|socket: &mut MySocket, json_req: String| -> Result<String, ApiClientError> {
				match socket.write_message(Message::Text(json_req.clone())) {
					Ok(_) => on_message_fn(socket),
					Err(e) => Err(ApiClientError::RpcClient(format!("{:?}", e))),
				}
			};

		while current_attempt <= self.max_attempts {
			match connect_with_config(url.clone(), None, self.max_attempts) {
				Ok(res) => {
					socket = res.0;
					let response = res.1;
					debug!("Connected to the server. Response HTTP code: {}", response.status());
					if socket.can_read() {
						current_attempt = 1;
						let ping = socket.read_message();
						if ping.is_err() {
							error!("failed to read ping message. error: {:?}", ping.unwrap_err());
						} else {
							debug!(
								"read ping message:{:?}. Connected successfully.",
								ping.unwrap()
							);

							//TODO remove
							// sleep(Duration::from_secs(1));

							match send_request(&mut socket, json_req.clone()) {
								Ok(e) => return Ok(e),
								Err(e) => {
									error!("failed to send request. error:{:?}", e);
									if current_attempt == self.max_attempts {
										return Err(e)
									}
								},
							};
						}
					}
					let _ = socket.close(Some(CloseFrame {
						code: CloseCode::Normal,
						reason: Default::default(),
					}));
				},
				Err(e) => {
					error!("failed to connect the server({:?}). error: {:?}", self.url, e);
				},
			};
			warn!(
				"attempt to request after {} sec. current attempt {}",
				5 * current_attempt,
				current_attempt
			);
			sleep(Duration::from_secs((5 * current_attempt) as u64));
			current_attempt += 1;
		}
		Err(ApiClientError::RpcClient("max request attempts exceeded".to_string()))
	}
}

impl RpcClientTrait for LitentryWsRpcClient {
	fn get_request(&self, jsonreq: Value) -> ApiResult<String> {
		self.direct_rpc_request(jsonreq.to_string(), on_get_request_msg)
	}

	fn send_extrinsic(&self, xthex_prefixed: String, exit_on: XtStatus) -> ApiResult<Option<Hash>> {
		let jsonreq = match exit_on {
			XtStatus::SubmitOnly => json_req::author_submit_extrinsic(&xthex_prefixed).to_string(),
			_ => json_req::author_submit_and_watch_extrinsic(&xthex_prefixed).to_string(),
		};
		match exit_on {
			XtStatus::Finalized => {
				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_finalized)?;
				info!("finalized: {}", res);
				Ok(Some(Hash::from_hex(res)?))
			},
			XtStatus::InBlock => {
				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_in_block)?;
				info!("inBlock: {}", res);
				Ok(Some(Hash::from_hex(res)?))
			},
			XtStatus::Broadcast => {
				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_broadcast)?;
				info!("broadcast: {}", res);
				Ok(None)
			},
			XtStatus::Ready => {
				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_ready)?;
				info!("ready: {}", res);
				Ok(None)
			},
			XtStatus::SubmitOnly => {
				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_submit_only)?;
				info!("submitted xt: {}", res);
				Ok(None)
			},
			_ => Err(ApiClientError::UnsupportedXtStatus(exit_on)),
		}
	}
}

impl Subscriber for LitentryWsRpcClient {
	fn start_subscriber(
		&self,
		json_req: String,
		result_in: ThreadOut<String>,
	) -> Result<(), ws::Error> {
		let url = Url::parse(self.url.as_str())
			.map_err(|e| ws::Error::new(ErrorKind::Internal, format!("{:?}", e)))?;
		let max_attempts = self.max_attempts;

		thread::spawn(move || {
			let mut current_attempt: u8 = 1;
			let mut socket: MySocket;

			while current_attempt <= max_attempts {
				match connect_with_config(url.clone(), None, max_attempts) {
					Ok(res) => {
						socket = res.0;
						let response = res.1;
						debug!(
							"Connected to the server. Response HTTP code: {}",
							response.status()
						);
						match socket.write_message(Message::Text(json_req.clone())) {
							Ok(_) => {},
							Err(e) => {
								error!("write msg error:{:?}", e);
							},
						}
						if socket.can_read() {
							current_attempt = 1;
							let msg_from_req = read_until_text_message(&mut socket);
							match msg_from_req {
								Ok(msg_from_req) => {
									debug!("response message: {:?}", msg_from_req);
									loop {
										let msg = read_until_text_message(&mut socket);
										if msg.is_err() {
											error!("err:{:?}", msg.unwrap_err());
											break
										}

										match on_subscription_msg(msg.unwrap()) {
											Ok(msg) =>
												if let Err(e) = result_in.send(msg) {
													error!("failed to send channel: {:?} ", e);
													return
												},
											Err(e) => {
												error!("on_subscription_msg: {:?}", e);
												return
											},
										}
									}
								},
								Err(e) => {
									error!("response message error:{:?}", e);
								},
							};
						}
						let _ = socket.close(Some(CloseFrame {
							code: CloseCode::Normal,
							reason: Default::default(),
						}));
					},
					Err(e) => {
						error!("failed to connect the server({:?}). error: {:?}", url, e);
					},
				};
				warn!(
					"attempt to request after {} sec. current attempt {}",
					5 * current_attempt,
					current_attempt
				);
				sleep(Duration::from_secs((5 * current_attempt) as u64));
				current_attempt += 1;
			}
			error!("max request attempts exceeded");
			// Err(ws::Error::new(ErrorKind::Internal, "max request attempts exceeded".to_string()))
		});
		Ok(())
	}
}

#[cfg(test)]
mod test {
	// use crate::{CreateNodeApi, NodeApiFactory};
	use crate::{message_handler::on_get_request_msg, LitentryWsRpcClient};
	use log::{info, warn};
	use sp_core::Pair;
	use std::{sync::mpsc::channel, thread::sleep, time::Duration};
	use substrate_api_client::{
		rpc::ws_client::Subscriber, std::rpc::json_req, Api, GenericAddress, IdentifyAccount,
		MultiSigner, PlainTipExtrinsicParams, XtStatus,
	};
	use tungstenite::{client::connect_with_config, connect, Message};
	use url::Url;

	fn init() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	// #[test]
	// fn test_direct_rpc_request() {
	// 	init();
	// 	let client = LitentryWsRpcClient {
	// 		url: "ws://host.docker.internal:9944".to_string(),
	// 		max_attempts: 3,
	// 	};
	// 	let result = client.direct_rpc_request(
	// 		json_req::chain_get_finalized_head().to_string(),
	// 		on_get_request_msg,
	// 	);
	// 	info!("chain_get_finalized_head:{:?}", result);
	// }
	//
	// #[test]
	// fn test_send_extrinsic() {
	// 	init();
	// 	let client = LitentryWsRpcClient {
	// 		url: "ws://host.docker.internal:9944".to_string(),
	// 		max_attempts: 3,
	// 	};
	// 	let alice = sp_core::sr25519::Pair::from_string("//Alice", None).unwrap();
	// 	let bob = sp_core::sr25519::Pair::from_string("//Bob", None).unwrap();
	//
	// 	info!("chain_get_finalized_head:{:?}", a);
	//
	// 	let api = Api::<sp_core::sr25519::Pair, LitentryWsRpcClient, PlainTipExtrinsicParams>::new(
	// 		client,
	// 	)
	// 	.unwrap();
	// 	let api = api.set_signer(alice);
	// 	let amount: u128 = 1000000000000;
	// 	let to_account = MultiSigner::from(bob.public()).into_account();
	// 	let xt = api.balance_transfer(GenericAddress::Id(to_account), amount);
	// 	let xt_hash = api.send_extrinsic(xt.hex_encode(), XtStatus::SubmitOnly).unwrap();
	//
	// 	info!("test a:{:?}", xt_hash);
	// }

	#[test]
	fn test_subscribe() {
		init();
		let client =
			LitentryWsRpcClient { url: "ws://localhost:9944".to_string(), max_attempts: 3 };
		let (thread_in, thread_out) = channel();

		// debug!("subscribing to finalized heads");
		let jsonreq = json_req::chain_subscribe_finalized_heads().to_string();
		let _ = client.start_subscriber(jsonreq, thread_in);
		loop {
			let block = thread_out.recv();
			warn!("new block:{:?}", block);
			if block.is_err() {
				sleep(Duration::from_secs(1));
				return
			}
		}
	}
}
