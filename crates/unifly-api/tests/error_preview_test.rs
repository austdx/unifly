//! Error-body previews retain their byte budget without splitting UTF-8.

use reqwest::Method;
use serde_json::{Value, json};
use unifly_api::{
    ControllerPlatform, Error, IntegrationClient, SessionClient, SiteManagerClient, TransportConfig,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn preview_cases() -> Vec<(String, String)> {
    vec![
        (String::new(), String::new()),
        ("short é🙂".into(), "short é🙂".into()),
        ("a".repeat(200), "a".repeat(200)),
        ("a".repeat(201), "a".repeat(200)),
        (format!("{}é trailing", "a".repeat(199)), "a".repeat(199)),
        (format!("{}€ trailing", "a".repeat(198)), "a".repeat(198)),
        (format!("{}🙂 trailing", "a".repeat(197)), "a".repeat(197)),
        (
            format!("{}€ trailing", "a".repeat(197)),
            format!("{}€", "a".repeat(197)),
        ),
    ]
}

fn assert_deserialization(error: Error, original: &str, preview: &str) {
    match error {
        Error::Deserialization { message, body } => {
            assert_eq!(body, original, "full error body must be preserved");
            assert!(
                message.ends_with(&format!("(body preview: {preview:?})")),
                "unexpected diagnostic: {message}"
            );
        }
        other => panic!("expected a deserialization error, got {other:?}"),
    }
}

fn assert_http_error(error: Error, preview: &str) {
    match error {
        Error::SessionApi { message } => {
            assert_eq!(message, format!("HTTP 502 Bad Gateway: {preview}"));
        }
        other => panic!("expected a Session HTTP error, got {other:?}"),
    }
}

async fn mock_body(server: &MockServer, verb: &Method, endpoint: &str, status: u16, body: &str) {
    server.reset().await;
    Mock::given(method(verb.as_str()))
        .and(path(endpoint))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .expect(1)
        .mount(server)
        .await;
}

fn session(server: &MockServer) -> SessionClient {
    SessionClient::new(
        server.uri().parse().expect("mock URL"),
        "default".into(),
        ControllerPlatform::ClassicController,
        &TransportConfig::default(),
    )
    .expect("Session client")
}

#[tokio::test]
async fn integration_malformed_json_preview_handles_utf8_boundaries() {
    let server = MockServer::start().await;
    let client = IntegrationClient::from_reqwest(
        &server.uri(),
        reqwest::Client::new(),
        ControllerPlatform::ClassicController,
    )
    .expect("Integration client");
    for (body, preview) in preview_cases() {
        mock_body(&server, &Method::GET, "/integration/v1/sites", 200, &body).await;
        assert_deserialization(
            client.list_sites(0, 25).await.expect_err("malformed JSON"),
            &body,
            &preview,
        );
    }
}

#[tokio::test]
async fn site_manager_malformed_json_preview_handles_utf8_boundaries() {
    let server = MockServer::start().await;
    let client = SiteManagerClient::from_reqwest(&server.uri(), reqwest::Client::new())
        .expect("Site Manager client");
    for (body, preview) in preview_cases() {
        mock_body(&server, &Method::GET, "/v1/hosts", 200, &body).await;
        assert_deserialization(
            client.list_hosts().await.expect_err("malformed JSON"),
            &body,
            &preview,
        );
    }
}

#[tokio::test]
async fn session_malformed_envelope_preview_handles_utf8_boundaries() {
    let server = MockServer::start().await;
    let client = session(&server);
    for (body, preview) in preview_cases() {
        mock_body(
            &server,
            &Method::GET,
            "/api/s/default/stat/device",
            200,
            &body,
        )
        .await;
        assert_deserialization(
            client.list_devices().await.expect_err("malformed envelope"),
            &body,
            &preview,
        );
    }
}

#[tokio::test]
async fn session_typed_http_error_preview_handles_utf8_boundaries() {
    let server = MockServer::start().await;
    let client = session(&server);
    for (body, preview) in preview_cases() {
        mock_body(
            &server,
            &Method::GET,
            "/api/s/default/stat/device",
            502,
            &body,
        )
        .await;
        assert_http_error(
            client.list_devices().await.expect_err("HTTP error"),
            &preview,
        );
    }
}

async fn raw_request(client: &SessionClient, verb: &Method) -> Result<Value, Error> {
    let endpoint = "v2/api/site/default/test";
    match *verb {
        Method::GET => client.raw_get(endpoint).await,
        Method::POST => client.raw_post(endpoint, &json!({})).await,
        Method::PUT => client.raw_put(endpoint, &json!({})).await,
        Method::PATCH => client.raw_patch(endpoint, &json!({})).await,
        Method::DELETE => client.raw_delete(endpoint).await.map(|()| Value::Null),
        _ => unreachable!("test only uses raw API methods"),
    }
}

#[tokio::test]
async fn session_raw_http_error_previews_handle_utf8_boundaries_for_every_method() {
    let server = MockServer::start().await;
    let client = session(&server);
    for verb in [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
    ] {
        for (body, preview) in preview_cases() {
            mock_body(&server, &verb, "/v2/api/site/default/test", 502, &body).await;
            assert_http_error(
                raw_request(&client, &verb).await.expect_err("HTTP error"),
                &preview,
            );
        }
    }
}
