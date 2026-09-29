use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::tests::controller;
use crate::ControllerPlatform;

#[tokio::test]
async fn raw_integration_redirect_never_sends_api_key_to_another_origin() {
    let server = MockServer::start().await;
    let other = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"leaked": true})))
        .mount(&other)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/redirect"))
        .and(header("X-API-KEY", "test-key"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", format!("{}/stolen", other.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = controller.raw_get("integration/v1/redirect").await;
    let forwarded = other.received_requests().await.expect("received requests");
    assert!(
        forwarded.is_empty(),
        "redirect forwarded credentials to another origin: {forwarded:?}"
    );
    assert!(result.is_err(), "unsafe redirect must not succeed");
}

#[tokio::test]
async fn raw_integration_redirect_stays_within_namespace_and_cloud_console() {
    for (platform, prefix, target) in [
        (
            ControllerPlatform::UnifiOs,
            "/proxy/network/integration",
            "/proxy/network/api/s/default/test",
        ),
        (
            ControllerPlatform::Cloud,
            "/v1/connector/consoles/test-console/proxy/network/integration",
            "/v1/connector/consoles/other-console/proxy/network/integration/v1/sites",
        ),
    ] {
        let server = MockServer::start().await;
        let controller = controller(&server, platform).await;
        server.reset().await;
        Mock::given(method("GET"))
            .and(path(format!("{prefix}/v1/redirect")))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", target))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(target))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"leaked": true})))
            .mount(&server)
            .await;
        let result = controller.raw_get("integration/v1/redirect").await;
        let requests = server.received_requests().await.expect("received requests");
        assert_eq!(
            requests.len(),
            1,
            "must not request another namespace or console"
        );
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn raw_integration_follows_same_namespace_redirects() {
    let server = MockServer::start().await;
    let controller = controller(&server, ControllerPlatform::UnifiOs).await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/redirect"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "/proxy/network/integration/v1/target"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/target"))
        .and(header("X-API-KEY", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        controller
            .raw_get("integration/v1/redirect")
            .await
            .expect("safe redirect"),
        json!({"ok": true})
    );
}
