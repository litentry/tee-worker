use lc_data_providers::discord_litentry::*;

#[cfg(test)]
use mockito::*;

//////////////////////////////////////////////////////////////////////////
///
/// discord_litentry
/// * check_join
/// * check_id_hubber
///
//////////////////////////////////////////////////////////////////////////
#[test]
fn test_check_join() {
	let guildid: u64 = 919848390156767232;
	let guild_id_vec: Vec<u8> = format!("{}", guildid).as_bytes().to_vec();
	let handler_vec: Vec<u8> = "againstwar%234779".as_bytes().to_vec();

	let body = DiscordResponse {
		data: true,
		message: "check join".into(),
		has_errors: false,
		msg_code: 200,
		success: true,
	};

	let _m = mock("GET", "/discord/joined")
		.match_query(Matcher::AllOf(vec![
			Matcher::UrlEncoded("guildid".into(), "919848390156767232".into()),
			Matcher::UrlEncoded("handler".into(), "againstwar%234779".into()),
		]))
		.with_status(200)
		.with_body(serde_json::to_string(&body).unwrap())
		.create();

	let mut client = DiscordLitentryClient::new();
	let response = client.check_join(guild_id_vec, handler_vec);

	assert!(response.is_ok(), "check join discord error: {:?}", response);
}

#[test]
fn test_check_id_hubber() 
{
    let guildid: u64 = 919848390156767232;
    let guild_id_vec: Vec<u8> = format!("{}", guildid).as_bytes().to_vec();
    let handler_vec: Vec<u8> = "ericzhang.eth%230114".as_bytes().to_vec();

	let body = DiscordResponse {
		data: true,
		message: "check id hubber.".into(),
		has_errors: false,
		msg_code: 200,
		success: true,
	};

	let _m = mock("GET", "/discord/commented/idhubber")
		.match_query(Matcher::AllOf(vec![
			Matcher::UrlEncoded("guildid".into(), "919848390156767232".into()),
			Matcher::UrlEncoded("handler".into(), "ericzhang.eth%230114".into()),
		]))
		.with_status(200)
		.with_body(serde_json::to_string(&body).unwrap())
		.create();

    let mut client = DiscordLitentryClient::new();
    let response = client.check_id_hubber(guild_id_vec, handler_vec);
    assert!(response.is_ok(), "check discord id hubber error: {:?}", response);
}

//////////////////////////////////////////////////////////////////////////
///
/// discord_official
/// * query_message
///
//////////////////////////////////////////////////////////////////////////

#[test]
fn test_query_message()
{
    
}