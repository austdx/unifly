use std::sync::Arc;

use reqwest::Method;
use secrecy::SecretString;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::{
    Controller, ControllerConfig, ControllerPlatform, CoreError, IntegrationClient, SessionClient,
    TransportConfig,
};

pub(super) async fn controller(server: &MockServer, platform: ControllerPlatform) -> Controller {
    let controller = Controller::new(ControllerConfig::default());
    let transport = TransportConfig::default();
    let base = if platform == ControllerPlatform::Cloud {
        format!("{}/v1/connector/consoles/test-console", server.uri())
    } else {
        server.uri()
    };
    let integration = IntegrationClient::from_api_key(
        &base,
        &SecretString::from("test-key"),
        &transport,
        platform,
    )
    .expect("integration client");
    *controller.inner.integration_client.lock().await = Some(Arc::new(integration));
    if platform != ControllerPlatform::Cloud {
        let login = platform.login_path().expect("local login path");
        Mock::given(method("POST"))
            .and(path(login))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Set-Cookie", "session=test-cookie; Path=/")
                    .insert_header("X-CSRF-Token", "test-csrf")
                    .set_body_json(json!({})),
            )
            .mount(server)
            .await;
        let session = SessionClient::new(
            server.uri().parse().expect("server URL"),
            "default".into(),
            platform,
            &transport,
        )
        .expect("session client");
        session
            .login("test-user", &SecretString::from("test-password"), None)
            .await
            .expect("mock login");
        *controller.inner.session_client.lock().await = Some(Arc::new(session));
    }
    controller
}

async fn request(
    controller: &Controller,
    verb: &Method,
    path: &str,
    body: &Value,
) -> Result<Value, CoreError> {
    match *verb {
        Method::GET => controller.raw_get(path).await,
        Method::POST => controller.raw_post(path, body).await,
        Method::PUT => controller.raw_put(path, body).await,
        Method::PATCH => controller.raw_patch(path, body).await,
        Method::DELETE => controller.raw_delete(path).await.map(|()| Value::Null),
        _ => unreachable!("test only supports CLI methods"),
    }
}

#[tokio::test]
async fn integration_raw_uses_api_key_for_every_method_and_platform() {
    for (platform, prefix) in [
        (ControllerPlatform::UnifiOs, "/proxy/network/integration"),
        (ControllerPlatform::ClassicController, "/integration"),
        (
            ControllerPlatform::Cloud,
            "/v1/connector/consoles/test-console/proxy/network/integration",
        ),
    ] {
        let server = MockServer::start().await;
        let controller = controller(&server, platform).await;
        for verb in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            let body = json!({"name": "test-policy"});
            let response = json!({"data": [{"unknownField": true}], "count": 1});
            let mut mock = Mock::given(method(verb.as_str()))
                .and(path(format!("{prefix}/v1/test")))
                .and(query_param("limit", "7"))
                .and(header("X-API-KEY", "test-key"))
                .and(|request: &wiremock::Request| !request.headers.contains_key("cookie"))
                .and(|request: &wiremock::Request| !request.headers.contains_key("X-CSRF-Token"));
            if matches!(verb, Method::POST | Method::PUT | Method::PATCH) {
                mock = mock.and(body_json(body.clone()));
            }
            mock.respond_with(if verb == Method::DELETE {
                ResponseTemplate::new(204)
            } else {
                ResponseTemplate::new(200).set_body_json(response.clone())
            })
            .expect(1)
            .mount(&server)
            .await;
            let actual = request(&controller, &verb, "integration/v1/test?limit=7", &body)
                .await
                .expect("raw integration request");
            assert_eq!(
                actual,
                if verb == Method::DELETE {
                    Value::Null
                } else {
                    response
                }
            );
        }
    }
}

/// Action endpoints (device/port actions) answer with 204 or an empty 200.
/// A raw call must report that as success, not as a JSON decode error,
/// or `unifly api … -m post` exits non-zero after the controller already
/// acted and invites a duplicate retry.
#[tokio::test]
async fn integration_raw_accepts_empty_success_responses() {
    for verb in [Method::GET, Method::POST, Method::PUT, Method::PATCH] {
        for (label, template) in [
            ("204", ResponseTemplate::new(204)),
            ("empty 200", ResponseTemplate::new(200)),
            (
                "whitespace 200",
                ResponseTemplate::new(200).set_body_string(" \n"),
            ),
        ] {
            let server = MockServer::start().await;
            let controller = controller(&server, ControllerPlatform::UnifiOs).await;
            Mock::given(method(verb.as_str()))
                .and(path("/proxy/network/integration/v1/devices/x/actions"))
                .respond_with(template)
                .expect(1)
                .mount(&server)
                .await;
            let body = json!({"action": "RESTART"});
            let actual = request(
                &controller,
                &verb,
                "integration/v1/devices/x/actions",
                &body,
            )
            .await
            .unwrap_or_else(|e| panic!("{verb} with {label} should succeed: {e}"));
            assert_eq!(actual, Value::Null, "{verb} with {label}");
        }
    }
}

#[tokio::test]
async fn session_raw_keeps_cookie_csrf_and_unwrapped_response_contract() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    for namespace in ["api/s/default/test", "v2/api/site/default/test"] {
        for verb in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            let body = json!({"enabled": false});
            let response = json!({"meta": {"rc": "ok"}, "data": [{"test": true}]});
            let mut mock = Mock::given(method(verb.as_str()))
                .and(path(format!("/proxy/network/{namespace}")))
                .and(header("cookie", "session=test-cookie"))
                .and(|request: &wiremock::Request| !request.headers.contains_key("X-API-KEY"));
            if verb != Method::GET {
                mock = mock.and(header("X-CSRF-Token", "test-csrf"));
            }
            if matches!(verb, Method::POST | Method::PUT | Method::PATCH) {
                mock = mock.and(body_json(body.clone()));
            }
            mock.respond_with(if verb == Method::DELETE {
                ResponseTemplate::new(204)
            } else {
                ResponseTemplate::new(200).set_body_json(response.clone())
            })
            .expect(1)
            .mount(&server)
            .await;
            let actual = request(&controller, &verb, namespace, &body)
                .await
                .expect("raw session request");
            assert_eq!(
                actual,
                if verb == Method::DELETE {
                    Value::Null
                } else {
                    response
                }
            );
        }
    }
}

#[tokio::test]
async fn integration_unauthorized_reports_api_key_failure_for_every_method() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    for verb in [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
    ] {
        Mock::given(method(verb.as_str()))
            .and(path("/proxy/network/integration/v1/denied"))
            .and(header("X-API-KEY", "test-key"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        let error = request(&controller, &verb, "integration/v1/denied", &json!({}))
            .await
            .expect_err("401 should fail");
        assert!(matches!(error, CoreError::AuthenticationFailed { message }
            if message == "Invalid API key"));
    }
}

#[tokio::test]
async fn integration_without_session_supports_leading_slash_and_query() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    *controller.inner.session_client.lock().await = None;
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/test"))
        .and(query_param("filter", "name=a/b"))
        .and(header("X-API-KEY", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(["raw", "array"])))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        controller
            .raw_get("/integration/v1/test?filter=name%3Da%2Fb")
            .await
            .expect("Integration does not need a Session client"),
        json!(["raw", "array"])
    );
}

#[tokio::test]
async fn integration_without_api_key_never_falls_back_to_cookie_auth() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    *controller.inner.integration_client.lock().await = None;
    server.reset().await;
    let result = controller.raw_get("integration/v1/sites").await;
    assert!(matches!(result, Err(CoreError::Unsupported { .. })));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn raw_rejects_ambiguous_paths_before_sending_any_request() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    server.reset().await;
    for path in [
        "",
        "/",
        "https://other.test/integration/v1/sites",
        "//other.test/path",
        "integration//other.test",
        "integration/",
        "integration/?query=1",
        "integration/v1/../../../api/s/default/test",
        "integration/v1/%2e%2e/test",
        "integration/v1/.%2E/test",
        "integration/v1/%252e%252e/test",
        "integration/v1/test%2F..%2F..",
        "integration/v1/test%5c..",
        "integration/v1\\test",
        "integration/v1/sites#fragment",
        "integration/v1/\nsites",
        " integration/v1/sites",
        "api/../integration/v1/sites",
    ] {
        for verb in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            let result = request(&controller, &verb, path, &json!({})).await;
            assert!(
                matches!(result, Err(CoreError::ValidationFailed { .. })),
                "{verb} {path:?}: {result:?}"
            );
        }
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn integration_prefix_is_anchored_to_a_complete_path_segment() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    for path_suffix in ["integration-extra/v1/test", "api/integration/v1/test"] {
        Mock::given(method("GET"))
            .and(path(format!("/proxy/network/{path_suffix}")))
            .and(header("cookie", "session=test-cookie"))
            .and(|request: &wiremock::Request| !request.headers.contains_key("X-API-KEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            controller
                .raw_get(path_suffix)
                .await
                .expect("Session namespace"),
            json!({"ok": true})
        );
    }
}

#[tokio::test]
async fn session_raw_preserves_mac_addresses_in_path_and_query() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    let endpoint = "v2/api/site/default/system-log/client-connection/02:00:00:00:00:01";
    Mock::given(method("GET"))
        .and(path(format!("/proxy/network/{endpoint}")))
        .and(query_param("mac", "02:00:00:00:00:01"))
        .and(header("cookie", "session=test-cookie"))
        .and(|request: &wiremock::Request| !request.headers.contains_key("X-API-KEY"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        controller
            .raw_get(&format!("{endpoint}?mac=02:00:00:00:00:01"))
            .await
            .expect("MAC in Session path is valid"),
        json!([])
    );
}
