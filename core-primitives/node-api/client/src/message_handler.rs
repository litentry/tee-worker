use crate::MySocket;
use log::{debug, error, info, warn};
use std::{
	string::{String, ToString},
	sync::mpsc::Sender as ThreadOut,
};
use substrate_api_client::{
	ApiClientError,
	ApiClientError::{Deserializing, Other, RpcClient},
	XtStatus,
};
use tungstenite::{
	protocol::{frame::coding::CloseCode, CloseFrame},
	Message,
};

pub type OnMessageFn = fn(socket: &mut MySocket) -> Result<String, ApiClientError>;

pub fn on_get_request_msg(socket: &mut MySocket) -> Result<String, ApiClientError> {
	let msg = read_until_text_message(socket).map_err(|e| RpcClient(format!("{:?}", e)))?;
	// let msg = socket.read_message().map_err(|e| RpcClient(format!("{:?}", e)))?;

	socket
		.close(Some(CloseFrame { code: CloseCode::Normal, reason: Default::default() }))
		.map_err(|e| RpcClient(format!("{:?}", e)))?;
	// println!("aaa {:?}", socket.read_message()); // close message
	debug!("Got get_request_msg {}", msg);
	let result_str = serde_json::from_str(msg.as_str())
		.map(|v: serde_json::Value| v["result"].to_string())
		.map_err(|e| Deserializing(e.into()))?;
	Ok(result_str)
}

pub fn on_extrinsic_msg_until_finalized(socket: &mut MySocket) -> Result<String, ApiClientError> {
	loop {
		let msg = read_until_text_message(socket).map_err(|e| RpcClient(format!("{:?}", e)))?;
		debug!("receive msg:{:?}", msg);
		match parse_status(msg) {
			Ok((XtStatus::Finalized, val)) => return end_process(socket, val),
			Ok((XtStatus::Future, _)) => {
				warn!("extrinsic has 'future' status. aborting");
				return end_process(socket, None)
			},
			Err(e) => {
				let _ = end_process(socket, None);
				return Err(RpcClient(format!("{:?}", e)))
			},
			_ => continue,
		}
	}
}

pub fn on_extrinsic_msg_until_in_block(socket: &mut MySocket) -> Result<String, ApiClientError> {
	loop {
		let msg = read_until_text_message(socket).map_err(|e| RpcClient(format!("{:?}", e)))?;
		match parse_status(msg) {
			Ok((XtStatus::Finalized, val)) => return end_process(socket, val),
			Ok((XtStatus::InBlock, val)) => return end_process(socket, val),
			Ok((XtStatus::Future, _)) => {
				warn!("extrinsic has 'future' status. aborting");
				return end_process(socket, None)
			},
			Err(e) => {
				let _ = end_process(socket, None);
				return Err(RpcClient(format!("{:?}", e)))
			},
			_ => continue,
		}
	}
}

pub fn on_extrinsic_msg_until_ready(socket: &mut MySocket) -> Result<String, ApiClientError> {
	loop {
		let msg = read_until_text_message(socket).map_err(|e| RpcClient(format!("{:?}", e)))?;
		match parse_status(msg) {
			Ok((XtStatus::Finalized, val)) => return end_process(socket, val),
			Ok((XtStatus::Ready, _)) => return end_process(socket, None),
			Ok((XtStatus::Future, _)) => {
				warn!("extrinsic has 'future' status. aborting");
				return end_process(socket, None)
			},
			Err(e) => {
				let _ = end_process(socket, None);
				return Err(RpcClient(format!("{:?}", e)))
			},
			_ => continue,
		}
	}
}

pub fn on_extrinsic_msg_until_broadcast(socket: &mut MySocket) -> Result<String, ApiClientError> {
	loop {
		let msg = read_until_text_message(socket).map_err(|e| RpcClient(format!("{:?}", e)))?;
		match parse_status(msg) {
			Ok((XtStatus::Finalized, val)) => return end_process(socket, val),
			Ok((XtStatus::Broadcast, _)) => return end_process(socket, None),
			Ok((XtStatus::Future, _)) => {
				warn!("extrinsic has 'future' status. aborting");
				return end_process(socket, None)
			},
			Err(e) => {
				let _ = end_process(socket, None);
				return Err(RpcClient(format!("{:?}", e)))
			},
			_ => continue,
		}
	}
}

pub fn on_extrinsic_msg_submit_only(socket: &mut MySocket) -> Result<String, ApiClientError> {
	loop {
		let msg = socket.read_message().map_err(|e| RpcClient(format!("{:?}", e)))?;
		debug!("got msg {}", msg);
		match result_from_json_response(msg) {
			Ok(None) => continue,
			Ok(Some(val)) => return end_process(socket, Some(val)),
			Err(e) => {
				let _ = end_process(socket, None)?;
				return Err(e)
			},
		}
	}
}

pub fn on_subscription_msg(msg: String) -> Result<String, ApiClientError> {
	info!("got on_subscription_msg {}", msg);
	let value: serde_json::Value =
		serde_json::from_str(msg.as_str()).map_err(|e| RpcClient(format!("{:?}", e)))?;

	match value["id"].as_str() {
		Some(_idstr) => {},
		_ => {
			// subscriptions
			debug!("no id field found in response. must be subscription");
			debug!("method: {:?}", value["method"].as_str());
			match value["method"].as_str() {
				Some("state_storage") => {
					let changes = &value["params"]["result"]["changes"];
					match changes[0][1].as_str() {
						Some(change_set) => return Ok(change_set.to_string()),
						None => println!("No events happened"),
					};
				},
				Some("chain_finalizedHead") => {
					let head = serde_json::to_string(&value["params"]["result"])
						.map_err(|e| RpcClient(format!("{:?}", e)))?;
					return Ok(head)
				},
				_ => error!("unsupported method"),
			}
		},
	};
	Ok("".to_string())
}

fn end_process(socket: &mut MySocket, val: Option<String>) -> Result<String, ApiClientError> {
	socket
		.close(Some(CloseFrame { code: CloseCode::Normal, reason: Default::default() }))
		.map_err(|e| RpcClient(format!("{:?}", e)))?;
	return Ok(val.unwrap_or("".to_string()))
}

fn parse_status(msg: String) -> Result<(XtStatus, Option<String>), ApiClientError> {
	let value: serde_json::Value = serde_json::from_str(msg.as_str())?;

	if value["error"].as_object().is_some() {
		return Err(into_extrinsic_err(&value))
	}

	match value["params"]["result"].as_object() {
		Some(obj) =>
			if let Some(hash) = obj.get("finalized") {
				info!("finalized: {:?}", hash);
				Ok((XtStatus::Finalized, Some(hash.to_string())))
			} else if let Some(hash) = obj.get("inBlock") {
				info!("inBlock: {:?}", hash);
				Ok((XtStatus::InBlock, Some(hash.to_string())))
			} else if let Some(array) = obj.get("broadcast") {
				info!("broadcast: {:?}", array);
				Ok((XtStatus::Broadcast, Some(array.to_string())))
			} else {
				Ok((XtStatus::Unknown, None))
			},
		None => match value["params"]["result"].as_str() {
			Some("ready") => Ok((XtStatus::Ready, None)),
			Some("future") => Ok((XtStatus::Future, None)),
			Some(&_) => Ok((XtStatus::Unknown, None)),
			None => Ok((XtStatus::Unknown, None)),
		},
	}
}

fn result_from_json_response(resp: Message) -> Result<Option<String>, ApiClientError> {
	if !match resp {
		Message::Text(_) => true,
		_ => false,
	} {
		return Ok(None)
	}

	let resp = resp.to_text().map_err(|e| Other(e.into()))?;
	let value: serde_json::Value = serde_json::from_str(resp)?;
	let resp = value["result"].as_str().ok_or_else(|| into_extrinsic_err(&value))?;

	Ok(Some(resp.to_string()))
}

/// Todo: this is the code that was used in `parse_status` Don't we want to just print the
/// error as is instead of introducing our custom format here?
fn into_extrinsic_err(resp_with_err: &serde_json::Value) -> ApiClientError {
	let err_obj = resp_with_err["error"].as_object().unwrap();

	let error = err_obj.get("message").map_or_else(|| "", |e| e.as_str().unwrap());
	let code = err_obj.get("code").map_or_else(|| -1, |c| c.as_i64().unwrap());
	let details = err_obj.get("data").map_or_else(|| "", |d| d.as_str().unwrap());

	RpcClient(format!("extrinsic error code {}: {}: {}", code, error, details))
}

pub(crate) fn read_until_text_message(socket: &mut MySocket) -> Result<String, tungstenite::Error> {
	loop {
		match socket.read_message() {
			Ok(Message::Text(s)) => {
				debug!("receive text: {:?}", s);
				break Ok(s)
			},
			Ok(Message::Binary(_)) => {
				debug!("skip binary msg");
			},
			Ok(Message::Ping(_)) => {
				debug!("skip ping msg");
			},
			Ok(Message::Pong(_)) => {
				debug!("skip ping msg");
			},
			Ok(Message::Close(_)) => {
				debug!("skip close msg");
			},
			Ok(Message::Frame(_)) => {
				debug!("skip frame msg");
			},
			Err(e) => break Err(e),
		}
	}
}
