use reqwest::redirect::Policy;
use url::Url;

use super::IntegrationClient;

impl IntegrationClient {
    /// `X-API-KEY` is a custom header: reqwest does not remove it on an
    /// off-origin redirect. Permit redirects only within this controller's
    /// Integration namespace, which also pins the cloud console when present.
    pub(super) fn redirect_policy(base_url: &Url) -> Policy {
        let origin = base_url.origin();
        let base_path = base_url.path().to_owned();
        Policy::custom(move |attempt| {
            let target = attempt.url();
            let encoded_path = target.path().to_ascii_lowercase();
            // Do not trust a downstream proxy to decode separators the same
            // way as URL normalization; nested escapes can hide traversal.
            let ambiguous_path = ["%2f", "%5c", "%25"]
                .iter()
                .any(|escape| encoded_path.contains(escape));
            if target.origin() != origin || !target.path().starts_with(&base_path) || ambiguous_path
            {
                attempt.stop()
            } else if attempt.previous().len() >= 10 {
                attempt.error("too many Integration API redirects")
            } else {
                attempt.follow()
            }
        })
    }
}
