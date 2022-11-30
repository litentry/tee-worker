/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0


	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

use crate::{global_components::GLOBAL_ATTESTATION_HANDLER_COMPONENT, ocall::OcallApi};
use itp_attestation_handler::{attestation_handler::SIGRL_SUFFIX, IasAttestationHandler, *};
use itp_component_container::ComponentGetter;
use itp_ocall_api::EnclaveAttestationOCallApi;
use std::{
	format,
	io::{Read, Write},
	net::TcpStream,
	sync::Arc,
	vec::Vec,
};

pub fn get_sigrl_from_intel_works() {
	let attestation_handler = GLOBAL_ATTESTATION_HANDLER_COMPONENT.get().unwrap();

	let init_quote = attestation_handler.ocall_api.sgx_init_quote().unwrap();
	let epid_group_id = init_quote.1;
	let eg_num = attestation_handler.as_u32_le(epid_group_id);

	let config = IasAttestationHandler::<OcallApi>::make_ias_client_config();
	let ias_socket = attestation_handler.ocall_api.get_ias_socket().unwrap();
	let ias_key = IasAttestationHandler::<OcallApi>::get_ias_api_key().unwrap();

	// GID: Base 16-encoded, encoded as a Big Endian integer.
	let gid = hex::encode(eg_num.to_be_bytes());
	let req = format!("GET {}{} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
					  SIGRL_SUFFIX,
					  gid,
					  DEV_HOSTNAME,
					  ias_key);

	let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
	let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
	let mut sock = TcpStream::new(ias_socket).unwrap();
	let mut tls = rustls::Stream::new(&mut sess, &mut sock);

	let _result = tls.write(req.as_bytes());
	let mut plaintext = Vec::new();
	let _ = tls.read_to_end(&mut plaintext);

	let mut headers = [httparse::EMPTY_HEADER; 16];
	let mut respp = httparse::Response::new(&mut headers);
	let _ = respp.parse(&plaintext);

	assert_eq!(respp.code, Some(200));
}
