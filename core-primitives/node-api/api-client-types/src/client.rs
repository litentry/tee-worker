// use log::{error, info, warn};
// use serde_json::Value;
// use sp_core::H256 as Hash;
// use std::{
// 	string::{String, ToString},
// 	sync::mpsc::{channel, Sender as ThreadOut},
// 	thread,
// 	thread::sleep,
// 	time::Duration,
// };
// use substrate_api_client::{
// 	std::{
// 		rpc::{
// 			json_req,
// 			ws_client::{
// 				on_extrinsic_msg_submit_only, on_extrinsic_msg_until_broadcast,
// 				on_extrinsic_msg_until_finalized, on_extrinsic_msg_until_in_block,
// 				on_extrinsic_msg_until_ready, on_get_request_msg, on_subscription_msg, OnMessageFn,
// 				Subscriber,
// 			},
// 		},
// 		FromHexString, RpcClient as RpcClientTrait,
// 	},
// 	ApiClientError, ApiResult, XtStatus,
// };
// use ws::{connect, CloseCode, ErrorKind, Handshake, Message, Result as WsResult, Sender};
//
// const DISCONNECTED: &str = "disconnected";
//
// pub struct LitentryRpcClient {
// 	pub out: Sender,
// 	pub request: String,
// 	pub result: ThreadOut<String>,
// 	pub on_message_fn: OnMessageFn,
// }
//
// impl ws::Handler for LitentryRpcClient {
// 	fn on_open(&mut self, _: Handshake) -> WsResult<()> {
// 		info!("sending request: {}", self.request);
// 		self.out.send(self.request.clone())?;
// 		Ok(())
// 	}
//
// 	fn on_message(&mut self, msg: Message) -> WsResult<()> {
// 		(self.on_message_fn)(msg, self.out.clone(), self.result.clone())
// 	}
//
// 	fn on_close(&mut self, code: CloseCode, reason: &str) {
// 		match code {
// 			CloseCode::Abnormal => {
// 				let _ = self.result.send(DISCONNECTED.to_string());
// 			},
// 			_ => {},
// 		}
// 		warn!("on_close: {:?},reason:{:?}", code, reason);
// 	}
//
// 	fn on_error(&mut self, err: ws::Error) {
// 		// Ignore connection reset errors by default, but allow library clients to see them by
// 		// overriding this method if they want
// 		if let ErrorKind::Io(ref err) = err.kind {
// 			log::error!("what error: {:?}", err);
// 			if let Some(104) = err.raw_os_error() {
// 				// Connection reset by peer
// 				return
// 			}
// 		}
// 		let _ = self.result.send(DISCONNECTED.to_string());
// 		log::error!("occur an error {:?}", err);
// 	}
// }
//
// #[derive(Debug, Clone)]
// pub struct LitentryWsRpcClient {
// 	url: String,
// 	max_attempts: u32,
// }
//
// impl LitentryWsRpcClient {
// 	pub fn new(url: &str, max_attempts: u32) -> LitentryWsRpcClient {
// 		LitentryWsRpcClient { url: url.to_string(), max_attempts }
// 	}
// }
//
// impl RpcClientTrait for LitentryWsRpcClient {
// 	fn get_request(&self, jsonreq: Value) -> ApiResult<String> {
// 		self.direct_rpc_request(jsonreq.to_string(), on_get_request_msg)
// 	}
//
// 	fn send_extrinsic(
// 		&self,
// 		xthex_prefixed: String,
// 		exit_on: XtStatus,
// 	) -> ApiResult<Option<sp_core::H256>> {
// 		// Todo: Make all variants return a H256: #175.
//
// 		let jsonreq = match exit_on {
// 			XtStatus::SubmitOnly => json_req::author_submit_extrinsic(&xthex_prefixed).to_string(),
// 			_ => json_req::author_submit_and_watch_extrinsic(&xthex_prefixed).to_string(),
// 		};
//
// 		match exit_on {
// 			XtStatus::Finalized => {
// 				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_finalized)?;
// 				info!("finalized: {}", res);
// 				Ok(Some(Hash::from_hex(res)?))
// 			},
// 			XtStatus::InBlock => {
// 				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_in_block)?;
// 				info!("inBlock: {}", res);
// 				Ok(Some(Hash::from_hex(res)?))
// 			},
// 			XtStatus::Broadcast => {
// 				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_broadcast)?;
// 				info!("broadcast: {}", res);
// 				Ok(None)
// 			},
// 			XtStatus::Ready => {
// 				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_until_ready)?;
// 				info!("ready: {}", res);
// 				Ok(None)
// 			},
// 			XtStatus::SubmitOnly => {
// 				let res = self.direct_rpc_request(jsonreq, on_extrinsic_msg_submit_only)?;
// 				info!("submitted xt: {}", res);
// 				Ok(None)
// 			},
// 			_ => Err(ApiClientError::UnsupportedXtStatus(exit_on)),
// 		}
// 	}
// }
//
// impl Subscriber for LitentryWsRpcClient {
// 	fn start_subscriber(
// 		&self,
// 		json_req: String,
// 		result_in: ThreadOut<String>,
// 	) -> Result<(), ws::Error> {
// 		self.start_subscriber(json_req, result_in)
// 	}
// }
//
// impl LitentryWsRpcClient {
// 	pub fn get(&self, json_req: String, result_in: ThreadOut<String>) -> WsResult<()> {
// 		self.start_rpc_client_thread(json_req, result_in, on_get_request_msg)
// 	}
//
// 	pub fn send_extrinsic(&self, json_req: String, result_in: ThreadOut<String>) -> WsResult<()> {
// 		self.start_rpc_client_thread(json_req, result_in, on_extrinsic_msg_submit_only)
// 	}
//
// 	pub fn send_extrinsic_until_ready(
// 		&self,
// 		json_req: String,
// 		result_in: ThreadOut<String>,
// 	) -> WsResult<()> {
// 		self.start_rpc_client_thread(json_req, result_in, on_extrinsic_msg_until_ready)
// 	}
//
// 	pub fn send_extrinsic_and_wait_until_broadcast(
// 		&self,
// 		json_req: String,
// 		result_in: ThreadOut<String>,
// 	) -> WsResult<()> {
// 		self.start_rpc_client_thread(json_req, result_in, on_extrinsic_msg_until_broadcast)
// 	}
//
// 	pub fn send_extrinsic_and_wait_until_in_block(
// 		&self,
// 		json_req: String,
// 		result_in: ThreadOut<String>,
// 	) -> WsResult<()> {
// 		self.start_rpc_client_thread(json_req, result_in, on_extrinsic_msg_until_in_block)
// 	}
//
// 	pub fn send_extrinsic_and_wait_until_finalized(
// 		&self,
// 		json_req: String,
// 		result_in: ThreadOut<String>,
// 	) -> WsResult<()> {
// 		self.start_rpc_client_thread(json_req, result_in, on_extrinsic_msg_until_finalized)
// 	}
//
// 	pub fn start_subscriber(&self, json_req: String, result_in: ThreadOut<String>) -> WsResult<()> {
// 		self.start_rpc_client_thread(json_req, result_in, on_subscription_msg)
// 	}
//
// 	fn start_rpc_client_thread(
// 		&self,
// 		jsonreq: String,
// 		result_in: ThreadOut<String>,
// 		on_message_fn: OnMessageFn,
// 	) -> WsResult<()> {
// 		let url = self.url.clone();
// 		let max_attempts = self.max_attempts;
// 		let (wrap_result_in, wrap_result_out) = channel::<String>();
// 		let (thread_in, thread_out) = channel::<u32>();
//
// 		thread::spawn(move || {
// 			let mut current_attempt: u32 = 0;
// 			let _ = thread_in.send(current_attempt);
// 			while current_attempt < max_attempts {
// 				match wrap_result_out.recv() {
// 					Ok(out) =>
// 						if out.as_str() == "disconnected" {
// 							warn!(
// 								"disconnected. attempt connect after {} sec. current attempt {}",
// 								5 * (current_attempt + 1),
// 								current_attempt
// 							);
// 							sleep(Duration::from_secs((5 * (current_attempt + 1)) as u64));
// 							let _ = thread_in.send(current_attempt);
// 							current_attempt += 1;
// 						} else {
// 							current_attempt = 0;
// 							let _ = result_in.send(out);
// 						},
// 					Err(e) => {
// 						log::error!("recvError 2: {:?}", e);
// 						break
// 					},
// 				}
// 			}
// 			let _ = thread_in.send(max_attempts);
// 		});
// 		thread::spawn(move || loop {
// 			match thread_out.recv() {
// 				Ok(current_attempt) => {
// 					if current_attempt >= max_attempts {
// 						error!("max connection attempts exceeded");
// 						break
// 					}
// 					let _ = connect(url.clone(), |out| LitentryRpcClient {
// 						out,
// 						request: jsonreq.clone(),
// 						result: wrap_result_in.clone(),
// 						on_message_fn,
// 					});
// 				},
// 				Err(e) => {
// 					log::error!("recvError: {:?}", e);
// 				},
// 			}
// 		});
// 		Ok(())
// 	}
//
// 	fn direct_rpc_request(&self, jsonreq: String, on_message_fn: OnMessageFn) -> ApiResult<String> {
// 		let (result_in, result_out) = channel();
// 		let mut current_attempt: u32 = 1;
//
// 		while current_attempt <= self.max_attempts {
// 			connect(self.url.clone(), |out| LitentryRpcClient {
// 				out,
// 				request: jsonreq.clone(),
// 				result: result_in.clone(),
// 				on_message_fn,
// 			})?;
// 			let out = result_out.recv()?;
// 			if out.as_str() == DISCONNECTED.to_string() {
// 				warn!(
// 					"attempt connect after {} sec. current attempt {}",
// 					5 * current_attempt,
// 					current_attempt
// 				);
// 				sleep(Duration::from_secs((5 * current_attempt) as u64));
// 				current_attempt += 1;
// 				continue
// 			} else {
// 				return Ok(out)
// 			}
// 		}
// 		Err(ApiClientError::RpcClient("max connection attempts exceeded".to_string()))
// 	}
// }