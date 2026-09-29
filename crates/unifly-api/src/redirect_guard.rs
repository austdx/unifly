// Redirect guard for clients that send `X-API-KEY`.
//
// reqwest strips `Authorization`, `Cookie`, `Proxy-Authorization` and
// `WWW-Authenticate` on a cross-host redirect, but not custom headers.
// Any client that carries the API key as a default header must therefore
// refuse to follow a redirect off its own origin, or the key goes with it.

use reqwest::redirect::Policy;
use url::Url;

/// Hop limit, matching reqwest's `Policy::default()` (`Policy::limited(10)`).
///
/// `Attempt::previous()` includes the initial URL, so reqwest errors only
/// once `previous().len() > 10`; comparing with `>=` would allow one fewer.
pub(crate) const MAX_REDIRECTS: usize = 10;

/// Percent-escapes that a downstream proxy may decode differently from URL
/// normalization. Nested escapes can hide separators or traversal.
pub(crate) const AMBIGUOUS_PATH_ESCAPES: [&str; 3] = ["%2f", "%5c", "%25"];

/// Whether `path` contains any escape from [`AMBIGUOUS_PATH_ESCAPES`]
/// (case-insensitive).
pub(crate) fn has_ambiguous_escape(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    AMBIGUOUS_PATH_ESCAPES
        .iter()
        .any(|escape| lowered.contains(escape))
}

/// Follow redirects only to `base_url`'s origin, and, when `path_prefix` is
/// set, only under that path. Anything else stops without following, so the
/// caller sees the 3xx instead of a response from another host.
pub(crate) fn same_origin_policy(base_url: &Url, path_prefix: Option<String>) -> Policy {
    let origin = base_url.origin();
    Policy::custom(move |attempt| {
        let target = attempt.url();
        let outside_prefix = path_prefix
            .as_deref()
            .is_some_and(|prefix| !target.path().starts_with(prefix));
        if target.origin() != origin || outside_prefix || has_ambiguous_escape(target.path()) {
            attempt.stop()
        } else if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn client(base: &str, prefix: Option<&str>) -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(same_origin_policy(
                &base.parse().unwrap(),
                prefix.map(str::to_owned),
            ))
            .build()
            .unwrap()
    }

    /// Mount a chain `/hop/0 -> /hop/1 -> … -> /hop/{hops}` that ends in 200.
    async fn mount_chain(server: &MockServer, hops: usize) {
        for i in 0..hops {
            Mock::given(method("GET"))
                .and(path(format!("/hop/{i}")))
                .respond_with(
                    ResponseTemplate::new(302).insert_header("Location", format!("/hop/{}", i + 1)),
                )
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(format!("/hop/{hops}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn follows_exactly_max_redirects_like_reqwest_default() {
        let server = MockServer::start().await;
        mount_chain(&server, MAX_REDIRECTS).await;
        let response = client(&server.uri(), None)
            .get(format!("{}/hop/0", server.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn errors_past_max_redirects() {
        let server = MockServer::start().await;
        mount_chain(&server, MAX_REDIRECTS + 1).await;
        let result = client(&server.uri(), None)
            .get(format!("{}/hop/0", server.uri()))
            .send()
            .await;
        assert!(result.unwrap_err().is_redirect());
    }

    #[tokio::test]
    async fn stops_at_cross_origin_redirect_without_contacting_target() {
        let server = MockServer::start().await;
        let other = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("Location", format!("{}/x", other.uri())),
            )
            .mount(&server)
            .await;
        let response = client(&server.uri(), None)
            .get(format!("{}/start", server.uri()))
            .header("X-API-KEY", "test-key")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            302,
            "redirect must be stopped, not followed"
        );
        assert!(other.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn prefix_and_escape_rules_stop_same_origin_redirects() {
        for target in ["/elsewhere", "/api/%2e%2e%2Fsecret", "/api/a%255c"] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/start"))
                .respond_with(ResponseTemplate::new(302).insert_header("Location", target))
                .mount(&server)
                .await;
            let response = client(&server.uri(), Some("/api/"))
                .get(format!("{}/api/start", server.uri()))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 302, "should stop at {target}");
        }
    }

    #[tokio::test]
    async fn keeps_api_key_on_allowed_redirect() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/start"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "/api/next"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/next"))
            .and(header("X-API-KEY", "test-key"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let response = client(&server.uri(), Some("/api/"))
            .get(format!("{}/api/start", server.uri()))
            .header("X-API-KEY", "test-key")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[test]
    fn detects_ambiguous_escapes_case_insensitively() {
        assert!(has_ambiguous_escape("/a%2Fb"));
        assert!(has_ambiguous_escape("/a%5cb"));
        assert!(has_ambiguous_escape("/a%25b"));
        assert!(!has_ambiguous_escape("/a%20b/c"));
    }
}
