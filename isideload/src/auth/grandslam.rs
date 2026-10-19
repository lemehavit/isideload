use super::middleware::WasmProxyMiddleware;
use plist::Dictionary;
use plist_macro::plist_to_xml_string;
use plist_macro::pretty_print_dictionary;
#[cfg(not(feature = "wasm"))]
use reqwest::Certificate;
use reqwest::{
    ClientBuilder,
    header::{HeaderMap, HeaderValue},
};
use reqwest_middleware::ClientBuilder as MwClientBuilder;
use rootcause::prelude::*;
use tracing::debug;

#[cfg(not(feature = "wasm"))]
use crate::sideload::cert_identity::APPLE_ROOT;
use crate::{SideloadError, anisette::AnisetteClientInfo, util::plist::PlistDataExtract};

const URL_BAG: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
// The Android AuthKit identity used for the -80045 workaround receives a
// provisioning-incompatible URL bag. Upstream uses this Mac/AuthKit identity
// for discovery only, while subsequent GrandSlam calls keep Android identity.
const URL_BAG_CLIENT_INFO: &str =
    "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";

pub struct GrandSlam {
    pub client: reqwest_middleware::ClientWithMiddleware,
    developer_client: reqwest_middleware::ClientWithMiddleware,
    pub client_info: AnisetteClientInfo,
    url_bag: Dictionary,
}

impl GrandSlam {
    /// Create a new GrandSlam instance
    ///
    /// # Arguments
    /// - `client`: The reqwest client to use for requests
    pub async fn new(
        client_info: AnisetteClientInfo,
        debug: bool,
        proxy_url: Option<String>,
    ) -> Result<Self, Report> {
        let client =
            Self::build_reqwest_client(debug, proxy_url.clone()).context("Failed to build HTTP client")?;
        let developer_client = Self::build_developer_client(proxy_url)
            .context("Failed to build Developer Services HTTP client")?;
        let base_headers = Self::base_headers(&client_info, false)?;
        let url_bag = Self::fetch_url_bag(&client, base_headers).await?;
        Ok(Self {
            client,
            developer_client,
            client_info,
            url_bag,
        })
    }

    /// Fetch the URL bag from GrandSlam and cache it
    pub async fn fetch_url_bag(
        client: &reqwest_middleware::ClientWithMiddleware,
        mut base_headers: HeaderMap,
    ) -> Result<Dictionary, Report> {
        debug!("Fetching URL bag from GrandSlam");
        base_headers.insert(
            "X-Mme-Client-Info",
            HeaderValue::from_str(URL_BAG_CLIENT_INFO)?,
        );
        let resp = client
            .get(URL_BAG)
            .headers(base_headers)
            .send()
            .await
            .context("Failed to fetch URL Bag")?
            .text()
            .await
            .context("Failed to read URL Bag response text")?;

        let dict: Dictionary =
            plist::from_bytes(resp.as_bytes()).context("Failed to parse URL Bag plist")?;
        let urls = dict
            .get("urls")
            .and_then(|v| v.as_dictionary())
            .cloned()
            .ok_or_else(|| report!("URL Bag plist missing 'urls' dictionary"))?;

        Ok(urls)
    }

    pub fn get_url(&self, key: &str) -> Result<String, Report> {
        let url = self
            .url_bag
            .get_string(key)
            .context("Unable to find key in URL bag")?;
        Ok(url)
    }

    pub fn get(&self, url: &str) -> Result<reqwest_middleware::RequestBuilder, Report> {
        let builder = self
            .client
            .get(url)
            .headers(Self::base_headers(&self.client_info, false)?);

        Ok(builder)
    }

    pub fn get_sms(&self, url: &str) -> Result<reqwest_middleware::RequestBuilder, Report> {
        let builder = self
            .client
            .get(url)
            .headers(Self::base_headers(&self.client_info, true)?);

        Ok(builder)
    }

    pub fn put_sms(&self, url: &str) -> Result<reqwest_middleware::RequestBuilder, Report> {
        let builder = self
            .client
            .put(url)
            .headers(Self::base_headers(&self.client_info, true)?);

        Ok(builder)
    }

    pub fn post(&self, url: &str) -> Result<reqwest_middleware::RequestBuilder, Report> {
        let builder = self
            .client
            .post(url)
            .headers(Self::base_headers(&self.client_info, false)?);

        Ok(builder)
    }

    pub fn post_developer(&self, url: &str) -> Result<reqwest_middleware::RequestBuilder, Report> {
        if !Self::developer_url_is_allowed(url) {
            bail!("Developer Services endpoint is not allowed");
        }
        Ok(self
            .developer_client
            .post(url)
            .headers(Self::base_headers(&self.client_info, false)?))
    }

    fn developer_url_is_allowed(value: &str) -> bool {
        let Ok(url) = reqwest::Url::parse(value) else { return false; };
        url.scheme() == "https"
            && url.host_str() == Some("developerservices2.apple.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.path().starts_with("/services/")
    }

    fn build_developer_client(
        proxy_url: Option<String>,
    ) -> Result<reqwest_middleware::ClientWithMiddleware, Report> {
        // Developer Services uses a public PKI chain, unlike GrandSlam's
        // private Apple root. Keep these trust policies on separate clients.
        #[cfg(not(feature = "wasm"))]
        let client = ClientBuilder::new()
            .http1_title_case_headers()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        #[cfg(feature = "wasm")]
        let client = ClientBuilder::new().build()?;
        let builder = MwClientBuilder::new(client);
        let builder = if let Some(proxy_url) = proxy_url {
            builder.with(WasmProxyMiddleware::new(proxy_url))
        } else {
            builder
        };
        Ok(builder.build())
    }

    pub fn post_sms(&self, url: &str) -> Result<reqwest_middleware::RequestBuilder, Report> {
        let builder = self
            .client
            .post(url)
            .headers(Self::base_headers(&self.client_info, true)?);

        Ok(builder)
    }

    pub fn patch(&self, url: &str) -> Result<reqwest_middleware::RequestBuilder, Report> {
        let client = if Self::developer_url_is_allowed(url) {
            &self.developer_client
        } else {
            &self.client
        };
        let builder = client
            .patch(url)
            .headers(Self::base_headers(&self.client_info, false)?);

        Ok(builder)
    }

    pub async fn plist_request(
        &self,
        url: &str,
        body: &Dictionary,
        additional_headers: Option<HeaderMap>,
    ) -> Result<Dictionary, Report> {
        let resp = self
            .post(url)?
            .headers(additional_headers.unwrap_or_else(reqwest::header::HeaderMap::new))
            .body(plist_to_xml_string(body))
            .send()
            .await
            .context("Failed to send grandslam request")?
            .error_for_status()
            .context("Received error response from grandslam")?
            .text()
            .await
            .context("Failed to read grandslam response as text")?;

        let dict: Dictionary = plist::from_bytes(resp.as_bytes())
            .context("Failed to parse grandslam response plist")
            .attach_with(|| resp.clone())?;

        let response_plist = dict
            .get("Response")
            .and_then(|v| v.as_dictionary())
            .cloned()
            .ok_or_else(|| {
                report!("grandslam response missing 'Response'")
                    .attach(pretty_print_dictionary(&dict))
            })?;

        Ok(response_plist)
    }

    fn base_headers(
        client_info: &AnisetteClientInfo,
        sms: bool,
    ) -> Result<reqwest::header::HeaderMap, Report> {
        let mut headers = reqwest::header::HeaderMap::new();
        if !sms {
            headers.insert("Content-Type", HeaderValue::from_static("text/x-xml-plist"));
            headers.insert("Accept", HeaderValue::from_static("text/x-xml-plist"));
        } else {
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));
            headers.insert("Accept", HeaderValue::from_static("application/json"));
        }
        headers.insert(
            "X-Mme-Client-Info",
            HeaderValue::from_str(&client_info.client_info)?,
        );
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(&client_info.user_agent)?,
        );
        headers.insert(
            "X-Xcode-Version",
            HeaderValue::from_static("27.0 (27A5218g)"),
        );
        headers.insert(
            "X-Apple-App-Info",
            HeaderValue::from_static("com.apple.gs.xcode.auth"),
        );
        headers.insert(
            reqwest::header::CONNECTION,
            HeaderValue::from_static("close"),
        );

        Ok(headers)
    }

    /// Build a reqwest client with the Apple root certificate
    ///
    /// # Arguments
    /// - `debug`: DANGER, If true, accept invalid certificates and enable verbose connection logging
    /// # Errors
    /// Returns an error if the reqwest client cannot be built
    pub fn build_reqwest_client(
        debug: bool,
        proxy_url: Option<String>,
    ) -> Result<reqwest_middleware::ClientWithMiddleware, Report> {
        #[cfg(not(feature = "wasm"))]
        let cert = Certificate::from_der(APPLE_ROOT)?;
        #[cfg(not(feature = "wasm"))]
        let client = ClientBuilder::new()
            // GrandSlam presents Apple's private PKI chain. Using the platform
            // verifier here still rejects the embedded Apple root on Debian.
            // Restrict this client to the pinned, repository-shipped Apple root
            // instead of changing the host-wide trust store.
            .tls_certs_only([cert])
            .http1_title_case_headers()
            .danger_accept_invalid_certs(debug)
            .connection_verbose(debug)
            .pool_max_idle_per_host(0)
            .build()?;
        #[cfg(feature = "wasm")]
        let client = ClientBuilder::new().build()?;

        let builder = MwClientBuilder::new(client);
        let builder = if let Some(proxy_url) = proxy_url {
            builder.with(WasmProxyMiddleware::new(proxy_url))
        } else {
            builder
        };
        Ok(builder.build())
    }
}

pub trait GrandSlamErrorChecker {
    fn check_grandslam_error(self) -> Result<Dictionary, Report<SideloadError>>;
}

impl GrandSlamErrorChecker for Dictionary {
    fn check_grandslam_error(self) -> Result<Self, Report<SideloadError>> {
        let result = match self.get("Status") {
            Some(plist::Value::Dictionary(d)) => d,
            _ => &self,
        };

        if result.get_signed_integer("ec").unwrap_or(0) != 0 {
            bail!(SideloadError::AuthWithMessage(
                result.get_signed_integer("ec").unwrap_or(-1),
                result.get_str("em").unwrap_or("Unknown error").to_string(),
            ))
        }

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_requests_accept_only_the_https_developer_services_origin() {
        assert!(GrandSlam::developer_url_is_allowed(
            "https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=XABBG36SBA"
        ));
        for denied in [
            "http://developerservices2.apple.com/services/QH65B2/listTeams.action",
            "https://gsa.apple.com/services/QH65B2/listTeams.action",
            "https://developerservices2.apple.com.example.org/services/QH65B2/listTeams.action",
            "https://user@developerservices2.apple.com/services/QH65B2/listTeams.action",
            "https://developerservices2.apple.com:444/services/QH65B2/listTeams.action",
        ] {
            assert!(!GrandSlam::developer_url_is_allowed(denied));
        }
    }

    #[test]
    #[ignore = "performs only an unauthenticated public HEAD request to Developer Services"]
    fn developer_public_tls_uses_public_roots_without_account_credentials() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime")
            .block_on(async {
                let client = GrandSlam::build_developer_client(None).expect("public-trust client");
                client
                    .head("https://developerservices2.apple.com/")
                    .timeout(std::time::Duration::from_secs(15))
                    .send()
                    .await
                    .expect("Developer Services public TLS certificate must validate");
            });
    }

    #[test]
    #[ignore = "contacts only Apple's public GrandSlam URL-bag endpoint"]
    fn public_url_bag_accepts_pinned_apple_root() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        runtime.block_on(async {
            let client_info = AnisetteClientInfo {
                client_info:
                    "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                        .to_string(),
                user_agent: "akd/1.0 CFNetwork/808.1.4".to_string(),
            };

            let grand_slam = GrandSlam::new(client_info, false, None)
                .await
                .expect("the pinned Apple root should validate the public GrandSlam URL bag");
            assert!(grand_slam.get_url("gsService").is_ok());
        });
    }

    #[test]
    fn url_bag_identity_is_separate_from_android_login_identity() {
        assert!(URL_BAG_CLIENT_INFO.contains("Mac15,7"));
        assert!(URL_BAG_CLIENT_INFO.contains("com.apple.AuthKit/1"));
        assert!(!URL_BAG_CLIENT_INFO.contains("Android"));
    }
}
