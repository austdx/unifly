#![allow(clippy::unwrap_used)]
//! Controller-level read-modify-write regressions for firewall endpoint filters.

use std::time::Duration;

use secrecy::SecretString;
use serde_json::{Value, json};
use unifly_api::{
    AuthCredentials, Command, Controller, ControllerConfig, CoreError, EntityId, TlsVerification,
    UpdateFirewallPolicyRequest,
};
use uuid::Uuid;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SITE_ID: &str = "00000000-0000-0000-0000-000000000001";
const POLICY_ID: &str = "00000000-0000-0000-0000-000000000002";
const MAC: &str = "02:00:00:00:00:01";

fn policy_path() -> String {
    format!("/proxy/network/integration/v1/sites/{SITE_ID}/firewall/policies/{POLICY_ID}")
}

fn existing_policy(kind: &str, mac: Value) -> Value {
    let mut source = json!({"type": kind});
    source["macAddressFilter"] = mac;
    match kind {
        "NETWORK" => {
            source["networkFilter"] = json!({"networkIds": [SITE_ID], "matchOpposite": true});
        }
        "IP_ADDRESS" => {
            source["ipAddressFilter"] = json!({
                "type": "IP_ADDRESSES",
                "items": [{"type": "IP_ADDRESS", "value": "192.0.2.1"}],
                "matchOpposite": false
            });
        }
        _ => panic!("unsupported synthetic filter kind"),
    }
    json!({
        "id": POLICY_ID, "name": "Original", "enabled": true,
        "action": {"type": "BLOCK"},
        "source": {"zoneId": SITE_ID, "trafficFilter": source},
        "destination": {
            "zoneId": SITE_ID,
            "trafficFilter": {
                "type": "DOMAIN",
                "domainFilter": {"type": "DOMAINS", "domains": ["example.com", "*.example.org"]},
                "portFilter": {"type": "PORTS", "items": [{"type": "PORT_NUMBER", "value": "443"}], "matchOpposite": false}
            }
        }
    })
}

async fn setup(existing: &Value) -> (MockServer, Controller) {
    let server = MockServer::start().await;
    // Low-priority collection fixtures cover the Controller's initial refresh.
    Mock::given(method("GET"))
        .and(path_regex("^/proxy/network/integration/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 200, "count": 0, "totalCount": 0, "data": []
        })))
        .with_priority(10)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/proxy/network/(api|v2)/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {"rc": "ok"}, "data": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy/network/integration/v1/sites"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 50, "count": 1, "totalCount": 1,
            "data": [{"id": SITE_ID, "internalReference": "default", "name": "Synthetic site"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(policy_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(existing))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(policy_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(existing))
        .mount(&server)
        .await;

    let controller = Controller::new(ControllerConfig {
        url: server.uri().parse().unwrap(),
        auth: AuthCredentials::ApiKey(SecretString::from("synthetic-key".to_owned())),
        site: "default".into(),
        tls: TlsVerification::SystemDefaults,
        timeout: Duration::from_secs(5),
        refresh_interval_secs: 0,
        websocket_enabled: false,
        polling_interval_secs: 3600,
        totp_token: None,
        profile_name: None,
        no_session_cache: true,
    });
    controller.connect().await.unwrap();
    (server, controller)
}

fn rename_command() -> Command {
    Command::UpdateFirewallPolicy {
        id: EntityId::Uuid(Uuid::parse_str(POLICY_ID).unwrap()),
        update: UpdateFirewallPolicyRequest {
            name: Some("Renamed".into()),
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn rename_preserves_string_mac_and_domain_filters_in_put_payload() {
    for kind in ["NETWORK", "IP_ADDRESS"] {
        let existing = existing_policy(kind, json!(MAC));
        let (server, controller) = setup(&existing).await;
        controller.execute(rename_command()).await.unwrap();
        controller.disconnect().await;

        let requests = server.received_requests().await.unwrap();
        let writes: Vec<_> = requests.iter().filter(|r| r.method == "PUT").collect();
        assert_eq!(writes.len(), 1);
        let body: Value = writes[0].body_json().unwrap();
        assert_eq!(body["name"], "Renamed");
        assert_eq!(body["action"], existing["action"]);
        assert_eq!(body["source"], existing["source"]);
        assert_eq!(body["destination"], existing["destination"]);
    }
}

#[tokio::test]
async fn rename_rejects_unrepresentable_mac_filter_before_any_put() {
    for kind in ["NETWORK", "IP_ADDRESS"] {
        for addresses in [json!([]), json!([MAC, "02:00:00:00:00:02"])] {
            let existing = existing_policy(kind, json!({"macAddresses": addresses}));
            let (server, controller) = setup(&existing).await;
            let result = controller.execute(rename_command()).await;
            controller.disconnect().await;

            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.iter().filter(|r| r.method == "PUT").count(), 0);
            match result {
                Err(CoreError::ValidationFailed { message }) => {
                    assert!(message.contains("source"));
                    assert!(message.contains("exactly one address"));
                }
                other => panic!("expected endpoint serialization error, got {other:?}"),
            }
        }
    }
}
