#![allow(clippy::unwrap_used)]
//! Synthetic wire fixtures for firewall filters from the Integration API.

use serde_json::{Value, json};
use unifly_api::integration_types::{DomainFilter, FirewallPolicyResponse, SourceTrafficFilter};
use unifly_api::{ControllerPlatform, FirewallPolicy, IntegrationClient};
use uuid::Uuid;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MAC: &str = "02:00:00:00:00:01";

fn source_filter(kind: &str, mac: Value) -> Value {
    let mut filter = json!({"type": kind});
    filter["macAddressFilter"] = mac;
    match kind {
        "NETWORK" => {
            filter["networkFilter"] = json!({"networkIds": [Uuid::nil()], "matchOpposite": true});
        }
        "IP_ADDRESS" => {
            filter["ipAddressFilter"] = json!({
                "type": "IP_ADDRESSES",
                "items": [{"type": "IP_ADDRESS", "value": "192.0.2.1"}],
                "matchOpposite": false
            });
        }
        _ => {}
    }
    filter
}

fn policy(source: Value, destination: Value) -> Value {
    let mut value = json!({
        "id": Uuid::nil(),
        "name": "Synthetic policy",
        "enabled": true,
        "action": {"type": "BLOCK"},
        "source": {},
        "destination": {}
    });
    value["source"]["trafficFilter"] = source;
    value["destination"]["trafficFilter"] = destination;
    value
}

#[test]
fn supplemental_mac_accepts_string_and_legacy_object_and_serializes_as_string() {
    for kind in ["NETWORK", "IP_ADDRESS"] {
        for mac in [json!(MAC), json!({"macAddresses": [MAC]})] {
            let filter: SourceTrafficFilter =
                serde_json::from_value(source_filter(kind, mac)).unwrap();
            let serialized = serde_json::to_value(&filter).unwrap();
            assert_eq!(serialized["macAddressFilter"], MAC);
            let reparsed: SourceTrafficFilter = serde_json::from_value(serialized).unwrap();
            assert_eq!(filter, reparsed);

            let response: FirewallPolicyResponse =
                serde_json::from_value(policy(serde_json::to_value(filter).unwrap(), Value::Null))
                    .unwrap();
            let rendered = serde_json::to_value(FirewallPolicy::from(response)).unwrap();
            assert_eq!(rendered["source"]["filter"]["mac_addresses"], json!([MAC]));
        }
    }
}

#[test]
fn supplemental_mac_absent_or_null_remains_unrestricted() {
    for kind in ["NETWORK", "IP_ADDRESS"] {
        for omit in [false, true] {
            let mut value = source_filter(kind, Value::Null);
            if omit {
                value.as_object_mut().unwrap().remove("macAddressFilter");
            }
            let filter: SourceTrafficFilter = serde_json::from_value(value).unwrap();
            let serialized = serde_json::to_value(filter).unwrap();
            assert!(serialized.get("macAddressFilter").is_none());
        }
    }
}

#[test]
fn malformed_supplemental_mac_is_rejected_without_coercion() {
    for kind in ["NETWORK", "IP_ADDRESS"] {
        for mac in [
            json!(42),
            json!(true),
            json!([MAC]),
            json!({}),
            json!({"macAddresses": MAC}),
            json!({"macAddresses": [42]}),
        ] {
            assert!(
                serde_json::from_value::<SourceTrafficFilter>(source_filter(kind, mac)).is_err()
            );
        }
    }
}

#[test]
fn supplemental_mac_serialization_never_discards_extra_addresses() {
    for kind in ["NETWORK", "IP_ADDRESS"] {
        for macs in [json!([]), json!([MAC, "02:00:00:00:00:02"])] {
            let value = source_filter(kind, json!({"macAddresses": macs}));
            let filter: SourceTrafficFilter = serde_json::from_value(value).unwrap();
            assert!(serde_json::to_value(filter).is_err());
        }
    }
}

#[test]
fn primary_mac_filter_keeps_object_shape_and_multiple_addresses() {
    let value = source_filter(
        "MAC_ADDRESS",
        json!({"macAddresses": [MAC, "02:00:00:00:00:02"]}),
    );
    let filter: SourceTrafficFilter = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(filter).unwrap(), value);
    assert!(
        serde_json::from_value::<SourceTrafficFilter>(source_filter("MAC_ADDRESS", json!(MAC)))
            .is_err()
    );
}

#[test]
fn domain_filter_accepts_both_tokens_and_writes_canonical_domains() {
    for kind in ["DOMAINS", "SPECIFIC"] {
        let filter: DomainFilter = serde_json::from_value(json!({
            "type": kind,
            "domains": ["example.com", "*.example.org"]
        }))
        .unwrap();
        assert_eq!(
            filter,
            DomainFilter::Specific {
                domains: vec!["example.com".into(), "*.example.org".into()]
            }
        );
        assert_eq!(
            serde_json::to_value(filter).unwrap(),
            json!({"type": "DOMAINS", "domains": ["example.com", "*.example.org"]})
        );
    }
}

#[test]
fn malformed_known_domain_filters_are_rejected() {
    for kind in ["DOMAINS", "SPECIFIC"] {
        for domains in [Value::Null, json!("example.com"), json!([42])] {
            assert!(
                serde_json::from_value::<DomainFilter>(json!({
                    "type": kind, "domains": domains
                }))
                .is_err()
            );
        }
        assert!(serde_json::from_value::<DomainFilter>(json!({"type": kind})).is_err());
    }
    assert_eq!(
        serde_json::from_value::<DomainFilter>(json!({"type": "FUTURE_FILTER"})).unwrap(),
        DomainFilter::Unknown
    );
}

#[tokio::test]
async fn list_and_get_retain_mac_and_domain_filters_through_model_conversion() {
    let server = MockServer::start().await;
    let client = IntegrationClient::from_reqwest(
        &server.uri(),
        reqwest::Client::new(),
        ControllerPlatform::ClassicController,
    )
    .unwrap();
    let site_id = Uuid::nil();
    let domain = json!({
        "type": "DOMAIN",
        "domainFilter": {"type": "DOMAINS", "domains": ["example.com", "*.example.org"]}
    });
    let policies: Vec<_> = ["NETWORK", "IP_ADDRESS"]
        .into_iter()
        .map(|kind| policy(source_filter(kind, json!(MAC)), domain.clone()))
        .collect();
    let malformed = policy(source_filter("NETWORK", json!(42)), Value::Null);
    let endpoint = format!("/integration/v1/sites/{site_id}/firewall/policies");
    Mock::given(method("GET"))
        .and(path(&endpoint))
        .and(query_param("offset", "0"))
        .and(query_param("limit", "25"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0, "limit": 25, "count": 3, "totalCount": 3,
            "data": [policies[0], policies[1], malformed]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{endpoint}/{site_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&policies[0]))
        .expect(1)
        .mount(&server)
        .await;

    let page = client
        .list_firewall_policies(&site_id, 0, 25)
        .await
        .unwrap();
    assert_eq!(page.count, 3, "wire count must survive rejected items");
    assert_eq!(page.total_count, 3);
    assert_eq!(
        page.data.len(),
        2,
        "only the malformed policy should be skipped"
    );
    let detail = client
        .get_firewall_policy(&site_id, &site_id)
        .await
        .unwrap();
    for response in page.data.into_iter().chain([detail]) {
        let rendered = serde_json::to_value(FirewallPolicy::from(response)).unwrap();
        assert_eq!(rendered["source"]["filter"]["mac_addresses"], json!([MAC]));
        assert_eq!(
            rendered["destination"]["filter"]["domains"],
            json!(["example.com", "*.example.org"])
        );
        assert_eq!(
            rendered["destination_summary"],
            "domain(example.com, *.example.org)"
        );
    }
}
