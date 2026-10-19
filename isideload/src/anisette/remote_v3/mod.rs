mod state;
mod websocket;

use std::sync::Arc;
use web_time::SystemTime;

use base64::prelude::*;
use plist_macro::plist;
use reqwest::{
    ClientBuilder,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use reqwest_middleware::ClientBuilder as MwClientBuilder;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::*;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::anisette::remote_v3::{state::AnisetteState, websocket::WsMessage};
use crate::anisette::{AnisetteClientInfo, AnisetteData, AnisetteProvider};
use crate::auth::grandslam::GrandSlam;
use crate::util::plist::PlistDataExtract;
use crate::util::storage::{SideloadingStorage, new_storage};
use crate::{SideloadError, anisette::remote_v3::websocket::AppWebSocket};

pub const DEFAULT_ANISETTE_V3_URL: &str = "https://ani.jkcoxson.com";
const CLIENT_INFO_PATH: &str = "/v3/client_info";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnisetteProvisioningStage {
    ProviderProvisionBegin,
    ClientInfoRequestBegin,
    ClientInfoRequestComplete,
    StateInitialized,
    WebSocketConnecting,
    WebSocketConnected,
    MessageReceived,
    MessageParsed,
    IdentifierSent,
    StartProvisioningRequestBegin,
    StartProvisioningRequestComplete,
    StartProvisioningRequestHttpFailure,
    StartProvisioningRequestTimeout,
    StartProvisioningRequestNetworkFailure,
    StartProvisioningResponseFailure,
    StartProvisioningDataSent,
    EndProvisioningRequestBegin,
    EndProvisioningRequestComplete,
    EndProvisioningDataSent,
    ProvisioningCommitted,
    StatePersisted,
    HeadersRequestBegin,
    HeadersRequestComplete,
}

impl AnisetteProvisioningStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderProvisionBegin => "PROVIDER_PROVISION_BEGIN",
            Self::ClientInfoRequestBegin => "CLIENT_INFO_REQUEST_BEGIN",
            Self::ClientInfoRequestComplete => "CLIENT_INFO_REQUEST_COMPLETE",
            Self::StateInitialized => "STATE_INITIALIZED",
            Self::WebSocketConnecting => "WEBSOCKET_CONNECTING",
            Self::WebSocketConnected => "WEBSOCKET_CONNECTED",
            Self::MessageReceived => "MESSAGE_RECEIVED",
            Self::MessageParsed => "MESSAGE_PARSED",
            Self::IdentifierSent => "IDENTIFIER_SENT",
            Self::StartProvisioningRequestBegin => "START_PROVISIONING_REQUEST_BEGIN",
            Self::StartProvisioningRequestComplete => "START_PROVISIONING_REQUEST_COMPLETE",
            Self::StartProvisioningRequestHttpFailure => "START_PROVISIONING_REQUEST_HTTP_FAILURE",
            Self::StartProvisioningRequestTimeout => "START_PROVISIONING_REQUEST_TIMEOUT",
            Self::StartProvisioningRequestNetworkFailure => {
                "START_PROVISIONING_REQUEST_NETWORK_FAILURE"
            }
            Self::StartProvisioningResponseFailure => "START_PROVISIONING_RESPONSE_FAILURE",
            Self::StartProvisioningDataSent => "START_PROVISIONING_DATA_SENT",
            Self::EndProvisioningRequestBegin => "END_PROVISIONING_REQUEST_BEGIN",
            Self::EndProvisioningRequestComplete => "END_PROVISIONING_REQUEST_COMPLETE",
            Self::EndProvisioningDataSent => "END_PROVISIONING_DATA_SENT",
            Self::ProvisioningCommitted => "PROVISIONING_COMMITTED",
            Self::StatePersisted => "STATE_PERSISTED",
            Self::HeadersRequestBegin => "HEADERS_REQUEST_BEGIN",
            Self::HeadersRequestComplete => "HEADERS_REQUEST_COMPLETE",
        }
    }
}

pub type AnisetteProvisioningDiagnosticSink =
    Arc<dyn Fn(AnisetteProvisioningStage) + Send + Sync + 'static>;

pub struct RemoteV3AnisetteProvider {
    pub state: Option<AnisetteState>,
    url: String,
    storage: Box<dyn SideloadingStorage>,
    serial_number: String,
    client: reqwest_middleware::ClientWithMiddleware,
    websocket_proxy: Option<String>,
    diagnostic_sink: Option<AnisetteProvisioningDiagnosticSink>,
}

impl RemoteV3AnisetteProvider {
    fn classify_start_provisioning_failure(report: &Report) -> AnisetteProvisioningStage {
        for context in report.as_ref().iter_reports() {
            if let Some(error) = context.downcast_current_context::<reqwest::Error>() {
                if error.status().is_some() {
                    return AnisetteProvisioningStage::StartProvisioningRequestHttpFailure;
                }
                if error.is_timeout() {
                    return AnisetteProvisioningStage::StartProvisioningRequestTimeout;
                }
                return AnisetteProvisioningStage::StartProvisioningRequestNetworkFailure;
            }
        }
        AnisetteProvisioningStage::StartProvisioningResponseFailure
    }

    /// Create a new RemoteV3AnisetteProvider with the given URL and config path
    ///
    /// # Arguments
    /// - `url`: The URL of the remote anisette service
    /// - `storage`: The storage backend for anisette data
    /// - `serial_number`: The serial number of the device
    pub fn new(
        url: &str,
        storage: Box<dyn SideloadingStorage>,
        serial_number: String,
    ) -> Result<Self, Report> {
        Ok(Self {
            state: None,
            url: url.to_string(),
            storage,
            serial_number,
            client: Self::build_reqwest_client(None)?,
            websocket_proxy: None,
            diagnostic_sink: None,
        })
    }

    pub fn set_websocket_proxy(mut self, websocket_proxy: Option<String>) -> Result<Self, Report> {
        self.websocket_proxy = websocket_proxy;
        self.client = Self::build_reqwest_client(self.websocket_proxy.clone())?;
        Ok(self)
    }

    fn build_reqwest_client(
        websocket_proxy: Option<String>,
    ) -> Result<reqwest_middleware::ClientWithMiddleware, Report> {
        if let Some(websocket_proxy) = websocket_proxy {
            use crate::auth::middleware::WasmProxyMiddleware;

            let client = ClientBuilder::new().build()?;

            Ok(MwClientBuilder::new(client)
                .with(WasmProxyMiddleware::new(websocket_proxy))
                .build())
        } else {
            let client = ClientBuilder::new().build()?;

            Ok(MwClientBuilder::new(client).build())
        }
    }

    pub fn default() -> Result<Self, Report> {
        Self::new(
            DEFAULT_ANISETTE_V3_URL,
            Box::new(new_storage()),
            "0".to_string(),
        )
    }

    pub fn set_url(mut self, url: &str) -> RemoteV3AnisetteProvider {
        self.url = url.to_string();
        self
    }

    pub fn set_storage(mut self, storage: Box<dyn SideloadingStorage>) -> RemoteV3AnisetteProvider {
        self.storage = storage;
        self
    }

    pub fn set_serial_number(mut self, serial_number: String) -> RemoteV3AnisetteProvider {
        self.serial_number = serial_number;
        self
    }

    pub fn set_diagnostic_sink(
        mut self,
        diagnostic_sink: Option<AnisetteProvisioningDiagnosticSink>,
    ) -> RemoteV3AnisetteProvider {
        self.diagnostic_sink = diagnostic_sink;
        self
    }

    fn emit(&self, stage: AnisetteProvisioningStage) {
        if let Some(sink) = &self.diagnostic_sink {
            sink(stage);
        }
    }
}

#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
impl AnisetteProvider for RemoteV3AnisetteProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteData, Report> {
        self.fetch_headers(None).await
    }

    async fn resync(&self, sim: &str) -> Result<AnisetteData, Report> {
        self.fetch_headers(Some(sim)).await
    }

    async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        self.emit(AnisetteProvisioningStage::ClientInfoRequestBegin);
        let info = self
            .client
            .get(format!("{}{}", self.url, CLIENT_INFO_PATH))
            .send()
            .await
            .context("Failed to request client info from anisette server")?
            .error_for_status()
            .context("Anisette server returned an error for client info")?
            .json::<AnisetteClientInfo>()
            .await
            .context("Failed to parse anisette client info response")?;
        self.emit(AnisetteProvisioningStage::ClientInfoRequestComplete);
        Ok(info)
    }

    fn needs_provisioning(&self) -> Result<bool, Report> {
        if let Some(state) = &self.state {
            Ok(!state.is_provisioned())
        } else {
            Ok(true)
        }
    }

    async fn provision(&mut self, gs: Arc<GrandSlam>) -> Result<(), Report> {
        self.emit(AnisetteProvisioningStage::ProviderProvisionBegin);
        self.get_client_info().await?;
        self.get_state(gs).await?;
        Ok(())
    }
}

impl RemoteV3AnisetteProvider {
    async fn fetch_headers(&self, sim: Option<&str>) -> Result<AnisetteData, Report> {
        self.emit(AnisetteProvisioningStage::HeadersRequestBegin);
        let state = self
            .state
            .as_ref()
            .ok_or(SideloadError::AnisetteNotProvisioned)?;
        let adi_pb = state
            .adi_pb
            .as_ref()
            .ok_or(SideloadError::AnisetteNotProvisioned)?;
        let client_info = self.get_client_info().await?;

        let mut body = serde_json::json!({
            "identifier": BASE64_STANDARD.encode(state.keychain_identifier),
            "adi_pb": BASE64_STANDARD.encode(adi_pb),
        });
        if let Some(sim) = sim {
            body["sim"] = serde_json::Value::String(sim.to_string());
            body["device_id"] = serde_json::Value::String(state.get_device_id());
            body["md_lu"] = serde_json::Value::String(hex::encode(state.get_md_lu()));
        }

        let headers = self
            .client
            .post(format!("{}/v3/get_headers", self.url))
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await?
            .error_for_status()?
            .json::<AnisetteHeaders>()
            .await?;

        let result = match headers {
            AnisetteHeaders::Headers {
                machine_id,
                one_time_password,
                routing_info,
            } => Ok(AnisetteData {
                machine_id,
                one_time_password,
                routing_info,
                _device_description: client_info.client_info.clone(),
                device_unique_identifier: state.get_device_id(),
                _local_user_id: hex::encode(state.get_md_lu()),
                generated_at: SystemTime::now(),
            }),
            AnisetteHeaders::GetHeadersError { message } => {
                Err(report!("Failed to get anisette headers").attach(message))
            }
        };
        if result.is_ok() {
            self.emit(AnisetteProvisioningStage::HeadersRequestComplete);
        }
        result
    }

    async fn get_state(&mut self, gs: Arc<GrandSlam>) -> Result<&mut AnisetteState, Report> {
        if self.state.is_none() {
            if let Ok(Some(state)) = &self.storage.retrieve_data("anisette_state") {
                if let Ok(state) = plist::from_bytes(state) {
                    info!("Loaded existing anisette state");
                    self.state = Some(state);
                } else {
                    warn!("Failed to parse existing anisette state, starting fresh");
                    self.state = Some(AnisetteState::new());
                }
            } else {
                info!("No existing anisette state found");
                self.state = Some(AnisetteState::new());
            }
            self.emit(AnisetteProvisioningStage::StateInitialized);
        }

        let diagnostic_sink = self.diagnostic_sink.clone();
        let state = self.state.as_mut().ok_or_report()?;
        if !state.is_provisioned() {
            info!("Provisioning required...");
            Self::provision(
                state,
                gs,
                &self.url,
                self.websocket_proxy.as_deref(),
                diagnostic_sink.as_ref(),
            )
                .await
                .context("Failed to provision")?;
        }
        let buf = Vec::new();
        let mut writer = std::io::BufWriter::new(buf);
        plist::to_writer_xml(&mut writer, &state)?;
        self.storage
            .store_data("anisette_state", &writer.into_inner()?)?;
        if let Some(sink) = &diagnostic_sink {
            sink(AnisetteProvisioningStage::StatePersisted);
        }

        Ok(state)
    }

    async fn provisioning_headers(state: &AnisetteState) -> Result<HeaderMap, Report> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Apple-I-MD-LU",
            HeaderValue::from_str(&hex::encode(state.get_md_lu()))?,
        );
        // headers.insert(
        //     "X-Apple-I-Client-Time",
        //     HeaderValue::from_str(
        //         &Utc::now()
        //             .round_subsecs(0)
        //             .format("%+")
        //             .to_string()
        //             .replace("+00:00", "Z"),
        //     )?,
        // );
        // headers.insert("X-Apple-I-TimeZone", HeaderValue::from_static("UTC"));
        // headers.insert("X-Apple-Locale", HeaderValue::from_static("en_US"));
        headers.insert(
            "X-Mme-Device-Id",
            HeaderValue::from_str(&state.get_device_id())?,
        );

        Ok(headers)
    }
    async fn provision(
        state: &mut AnisetteState,
        gs: Arc<GrandSlam>,
        url: &str,
        proxy_url: Option<&str>,
        diagnostic_sink: Option<&AnisetteProvisioningDiagnosticSink>,
    ) -> Result<(), Report> {
        let emit = |stage| {
            if let Some(sink) = diagnostic_sink {
                sink(stage);
            }
        };
        let start_provisioning = gs.get_url("midStartProvisioning")?;
        let end_provisioning = gs.get_url("midFinishProvisioning")?;

        let websocket_url = format!("{}/v3/provisioning_session", url)
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        debug!("Starting provisioning at {}", websocket_url);
        // let (mut ws_stream, _) = timeout(
        //     Duration::from_secs(30),
        //     tokio_tungstenite::connect_async(&websocket_url),
        // )
        // .await
        // .map_err(|_| {
        //     report!("Timed out connecting to provisioning socket. Try a different anisette server.")
        // })
        // .context("Failed to connect to provisioning socket")?
        // .context("Failed to connect to provisioning socket")?;

        emit(AnisetteProvisioningStage::WebSocketConnecting);
        let mut ws = AppWebSocket::connect(&websocket_url, proxy_url)
            .await
            .context("Failed to connect to provisioning socket")?;
        emit(AnisetteProvisioningStage::WebSocketConnected);

        debug!("Connected to provisioning socket");

        loop {
            let Some(msg) = ws.next().await else { continue };
            let msg = msg?;
            emit(AnisetteProvisioningStage::MessageReceived);

            let text = match msg {
                WsMessage::Close => bail!("Provisioning socket closed unexpectedly"),
                WsMessage::Text(t) => t,
            };

            debug!("Received provisioning message: {}", text);
            let provision_msg: ProvisioningMessage = serde_json::from_str(&text)?;
            emit(AnisetteProvisioningStage::MessageParsed);

            match provision_msg {
                ProvisioningMessage::GiveIdentifier => {
                    ws.send_text(
                        serde_json::json!({
                            "identifier": BASE64_STANDARD.encode(state.keychain_identifier),
                        })
                        .to_string()
                        .into(),
                    )
                    .await
                    .context("Failed to send identifier")?;
                    emit(AnisetteProvisioningStage::IdentifierSent);
                }
                ProvisioningMessage::GiveStartProvisioningData => {
                    let body = plist!(dict {
                        "Header": {},
                        "Request": {}
                    });

                    emit(AnisetteProvisioningStage::StartProvisioningRequestBegin);
                    let response = match gs
                        .plist_request(
                            &start_provisioning,
                            &body,
                            Some(Self::provisioning_headers(state).await?),
                        )
                        .await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            emit(Self::classify_start_provisioning_failure(&error));
                            return Err(
                                error
                                    .context("Failed to send start provisioning request")
                                    .into(),
                            );
                        }
                    };
                    emit(AnisetteProvisioningStage::StartProvisioningRequestComplete);

                    let spim = response
                        .get_str("spim")
                        .context("Start provisioning response missing spim")?;

                    ws.send_text(
                        serde_json::json!({
                            "spim": spim,
                        })
                        .to_string()
                        .into(),
                    )
                    .await
                    .context("Failed to send start provisioning data")?;
                    emit(AnisetteProvisioningStage::StartProvisioningDataSent);
                }
                ProvisioningMessage::GiveEndProvisioningData { cpim } => {
                    let body = plist!(dict {
                        "Header": {},
                        "Request": {
                            "cpim": cpim,
                        }
                    });

                    emit(AnisetteProvisioningStage::EndProvisioningRequestBegin);
                    let response = gs
                        .plist_request(
                            &end_provisioning,
                            &body,
                            Some(Self::provisioning_headers(state).await?),
                        )
                        .await
                        .context("Failed to send end provisioning request")?;
                    emit(AnisetteProvisioningStage::EndProvisioningRequestComplete);

                    ws.send_text(
                        serde_json::json!({
                            "ptm": response
                                .get_str("ptm")
                                .context("End provisioning response missing ptm")?,
                            "tk": response
                                .get_str("tk")
                                .context("End provisioning response missing tk")?,
                        })
                        .to_string()
                        .into(),
                    )
                    .await
                    .context("Failed to send start provisioning data")?;
                    emit(AnisetteProvisioningStage::EndProvisioningDataSent);
                }
                ProvisioningMessage::ProvisioningSuccess { adi_pb } => {
                    state.adi_pb = Some(BASE64_STANDARD.decode(adi_pb)?);
                    emit(AnisetteProvisioningStage::ProvisioningCommitted);
                    ws.close().await?;
                    info!("Provisioning successful");
                    break;
                }
                ProvisioningMessage::Timeout => bail!("Anisette provisioning timed out"),
                ProvisioningMessage::InvalidIdentifier => {
                    bail!("Anisette provisioning failed: invalid identifier")
                }
                ProvisioningMessage::StartProvisioningError { message } => {
                    return Err(
                        report!("Anisette provisioning failed: start provisioning error")
                            .attach(message),
                    );
                }
                ProvisioningMessage::EndProvisioningError { message } => {
                    return Err(
                        report!("Anisette provisioning failed: end provisioning error")
                            .attach(message),
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "result")]
enum ProvisioningMessage {
    GiveIdentifier,
    GiveStartProvisioningData,
    GiveEndProvisioningData { cpim: String },
    ProvisioningSuccess { adi_pb: String },
    Timeout,
    InvalidIdentifier,
    StartProvisioningError { message: String },
    EndProvisioningError { message: String },
}

#[derive(Deserialize)]
#[serde(tag = "result")]
enum AnisetteHeaders {
    GetHeadersError {
        message: String,
    },
    Headers {
        #[serde(rename = "X-Apple-I-MD-M")]
        machine_id: String,
        #[serde(rename = "X-Apple-I-MD")]
        one_time_password: String,
        #[serde(rename = "X-Apple-I-MD-RINFO")]
        routing_info: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_v3_uses_upstream_dynamic_client_info_endpoint() {
        assert_eq!(DEFAULT_ANISETTE_V3_URL, "https://ani.jkcoxson.com");
        assert_eq!(CLIENT_INFO_PATH, "/v3/client_info");
    }

    #[test]
    fn provisioning_diagnostic_stages_are_bounded_categories() {
        let stages = [
            AnisetteProvisioningStage::ProviderProvisionBegin,
            AnisetteProvisioningStage::WebSocketConnected,
            AnisetteProvisioningStage::StartProvisioningRequestBegin,
            AnisetteProvisioningStage::EndProvisioningRequestComplete,
            AnisetteProvisioningStage::HeadersRequestComplete,
        ];

        for stage in stages {
            let value = stage.as_str();
            assert!(!value.is_empty());
            assert!(value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_'));
        }
    }
}
