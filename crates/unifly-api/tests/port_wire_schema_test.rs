#![allow(clippy::unwrap_used)]
//! Port matching writes follow the UniFi OpenAPI integer wire schema.

use serde_json::json;
use unifly_api::integration_types::PortItem;

#[test]
fn range_reads_accept_legacy_names_but_always_write_numeric_start_stop() {
    for wire in [
        json!({"type": "PORT_NUMBER_RANGE", "start": 8000, "stop": 9000}),
        json!({"type": "PORT_NUMBER_RANGE", "start": "8000", "stop": "9000"}),
        json!({"type": "PORT_RANGE", "startPort": "8000", "endPort": 9000}),
    ] {
        let item: PortItem = serde_json::from_value(wire).unwrap();
        let canonical = json!({"type": "PORT_NUMBER_RANGE", "start": 8000, "stop": 9000});
        assert_eq!(serde_json::to_value(&item).unwrap(), canonical);
        assert_eq!(serde_json::from_value::<PortItem>(canonical).unwrap(), item);
    }
}

#[test]
fn individual_ports_write_numbers_at_schema_boundaries() {
    for port in [1, 443, 65535] {
        for value in [json!(port), json!(port.to_string())] {
            let item: PortItem =
                serde_json::from_value(json!({"type": "PORT_NUMBER", "value": value})).unwrap();
            assert_eq!(
                serde_json::to_value(item).unwrap(),
                json!({"type": "PORT_NUMBER", "value": port})
            );
        }
    }
}

#[test]
fn invalid_port_values_cannot_be_serialized_into_requests() {
    for invalid in ["0", "65536", "-1", "443.5", "https", ""] {
        for item in [
            PortItem::Number {
                value: invalid.into(),
            },
            PortItem::Range {
                start_port: invalid.into(),
                end_port: "65535".into(),
            },
            PortItem::Range {
                start_port: "1".into(),
                end_port: invalid.into(),
            },
        ] {
            assert!(
                serde_json::to_value(item).is_err(),
                "accepted invalid port {invalid:?}"
            );
        }
    }
}
