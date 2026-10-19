use std::{future::Future, sync::Arc};

use crate::{
    SideloadError,
    anisette::{AnisetteData, AnisetteDataGenerator},
    auth::{
        builder::AppleAccountBuilder,
        grandslam::{GrandSlam, GrandSlamErrorChecker},
    },
    util::plist::{PlistDataExtract, SensitivePlistAttachment},
};
use aes::{
    Aes256,
    cipher::{block_padding::Pkcs7, consts::U16},
};
use aes_gcm::{AeadInOut, AesGcm, KeyInit, Nonce};
use base64::{Engine, prelude::BASE64_STANDARD};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use plist::Dictionary;
use plist_macro::plist;
use reqwest::header::{HeaderMap, HeaderValue};
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use srp::{ClientVerifier, groups::G2048};
use tracing::{debug, info, warn};

pub struct AppleAccount {
    pub email: String,
    pub spd: Option<plist::Dictionary>,
    pub anisette_generator: AnisetteDataGenerator,
    pub grandslam_client: Arc<GrandSlam>,
    pub trusted_phone_numbers: Option<Vec<TrustedNumber>>,
    login_state: LoginState,
    debug: bool,
    last_error: Option<String>,
    preflight_xcode_token: Option<AppToken>,
}

#[derive(Debug, Clone)]
pub enum LoginState {
    LoggedIn,
    NeedsDevice2FA,
    NeedsDevice2FAVerification,
    NeedsSMS2FA(u32),
    NeedsSMS2FAVerification(u32),
    NeedsUnknown2FA,
    NeedsExtraStep(String),
    NeedsLogin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostTwoFactorDiagnosticResult {
    Success,
    HttpStatus(u16),
    AppleServiceCode(i64),
    ResponseBodyFailure,
    PlistParseFailure,
    TransportFailure,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostTwoFactorLoginStage {
    InitialLogin,
    ProofLogin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostTwoFactorDiagnosticEvent {
    TrustedDeviceVerifyBegin,
    TrustedDeviceVerifySuccess,
    TrustedDeviceVerifyRejected {
        apple_service_code: i64,
    },
    TrustedDeviceVerifyFailure {
        result: PostTwoFactorDiagnosticResult,
    },
    TransitionToNeedsLogin,
    TransitionToNeedsDevice2FAVerification,
    PostTwoFactorInitialLoginBegin,
    PostTwoFactorInitialLoginResponseResult {
        result: PostTwoFactorDiagnosticResult,
    },
    PostTwoFactorProofLoginBegin,
    PostTwoFactorProofLoginResponseResult {
        result: PostTwoFactorDiagnosticResult,
    },
    TransitionToNeedsDevice2FA {
        preceding_stage: PostTwoFactorLoginStage,
    },
}

pub type PostTwoFactorDiagnosticSink = Arc<dyn Fn(PostTwoFactorDiagnosticEvent) + Send + Sync>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TrustedNumber {
    pub number_with_dial_code: String,
    pub last_two_digits: String,
    pub push_mode: String,
    pub id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorCallbackParams {
    pub last_error: Option<String>,
    // If this is true, we don't know what's going to work, so present the user with all the options and let them choose
    pub unknown: bool,
    pub sms: bool,
    pub numbers: Vec<TrustedNumber>,
    pub selected_number_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TwoFactorCallbackResponse {
    SubmitCode(String),
    SendSms(u32),
    SendToDevices,
    ResendCode,
    Abort,
}

#[derive(Debug, Clone)]
pub struct SMSTwoFactorError {
    pub code: String,
    pub title: String,
    pub message: String,
}

fn resync_sim(response: &Dictionary) -> Option<String> {
    let status = response.get("Status")?.as_dictionary()?;
    if status
        .get("hsc")
        .and_then(plist::Value::as_signed_integer)
        != Some(434)
    {
        return None;
    }

    match status.get("X-Apple-I-MD-DATA")? {
        plist::Value::Data(data) => Some(BASE64_STANDARD.encode(data)),
        plist::Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn emit_post_two_factor_diagnostic(
    sink: Option<&PostTwoFactorDiagnosticSink>,
    event: PostTwoFactorDiagnosticEvent,
) {
    if let Some(sink) = sink {
        sink(event);
    }
}

fn post_two_factor_result_from_report(report: &Report) -> PostTwoFactorDiagnosticResult {
    for cause in report.as_ref().iter_reports() {
        if let Some(error) = cause.downcast_current_context::<SideloadError>()
            && let SideloadError::AuthWithMessage(code, _) = error
        {
            return PostTwoFactorDiagnosticResult::AppleServiceCode(*code);
        }
        if let Some(error) = cause.downcast_current_context::<reqwest::Error>()
            && let Some(status) = error.status()
        {
            return PostTwoFactorDiagnosticResult::HttpStatus(status.as_u16());
        }
    }
    PostTwoFactorDiagnosticResult::TransportFailure
}

fn report_has_apple_service_code(report: &Report, expected: i64) -> bool {
    report.as_ref().iter_reports().any(|cause| {
        matches!(
            cause.downcast_current_context::<SideloadError>(),
            Some(SideloadError::AuthWithMessage(code, _)) if *code == expected
        )
    })
}

fn emit_post_two_factor_login_begin(
    stage: PostTwoFactorLoginStage,
    sink: Option<&PostTwoFactorDiagnosticSink>,
) {
    let event = match stage {
        PostTwoFactorLoginStage::InitialLogin => {
            PostTwoFactorDiagnosticEvent::PostTwoFactorInitialLoginBegin
        }
        PostTwoFactorLoginStage::ProofLogin => {
            PostTwoFactorDiagnosticEvent::PostTwoFactorProofLoginBegin
        }
    };
    emit_post_two_factor_diagnostic(sink, event);
}

fn emit_post_two_factor_login_response_result(
    stage: PostTwoFactorLoginStage,
    result: PostTwoFactorDiagnosticResult,
    sink: Option<&PostTwoFactorDiagnosticSink>,
) {
    let event = match stage {
        PostTwoFactorLoginStage::InitialLogin => {
            PostTwoFactorDiagnosticEvent::PostTwoFactorInitialLoginResponseResult { result }
        }
        PostTwoFactorLoginStage::ProofLogin => {
            PostTwoFactorDiagnosticEvent::PostTwoFactorProofLoginResponseResult { result }
        }
    };
    emit_post_two_factor_diagnostic(sink, event);
}

fn classify_post_two_factor_login_state(
    status: &Dictionary,
    sink: Option<&PostTwoFactorDiagnosticSink>,
) -> LoginState {
    if let Some(plist::Value::String(s)) = status.get("au") {
        return match s.as_str() {
            "trustedDeviceSecondaryAuth" => {
                emit_post_two_factor_diagnostic(
                    sink,
                    PostTwoFactorDiagnosticEvent::TransitionToNeedsDevice2FA {
                        preceding_stage: PostTwoFactorLoginStage::ProofLogin,
                    },
                );
                LoginState::NeedsDevice2FA
            }
            "secondaryAuth" => LoginState::NeedsSMS2FA(1),
            "repair" => LoginState::LoggedIn,
            unknown => LoginState::NeedsExtraStep(unknown.to_string()),
        };
    }
    LoginState::LoggedIn
}

fn classify_login_response(
    stage: PostTwoFactorLoginStage,
    response: Result<Dictionary, Report>,
    sink: Option<&PostTwoFactorDiagnosticSink>,
    request_context: &'static str,
    response_context: &'static str,
) -> Result<Dictionary, Report> {
    let response = match response {
        Ok(response) => response,
        Err(report) => {
            let report = report.context(request_context).into_dynamic();
            emit_post_two_factor_login_response_result(
                stage,
                post_two_factor_result_from_report(&report),
                sink,
            );
            return Err(report);
        }
    };
    match response.check_grandslam_error() {
        Ok(response) => {
            emit_post_two_factor_login_response_result(
                stage,
                PostTwoFactorDiagnosticResult::Success,
                sink,
            );
            Ok(response)
        }
        Err(report) => {
            let report = report.context(response_context).into_dynamic();
            emit_post_two_factor_login_response_result(
                stage,
                post_two_factor_result_from_report(&report),
                sink,
            );
            Err(report)
        }
    }
}

fn classify_trusted_device_response(
    res: Result<Dictionary, Report>,
    last_error: &mut Option<String>,
    sink: Option<&PostTwoFactorDiagnosticSink>,
) -> Result<LoginState, Report> {
    if let Err(report) = &res {
        for cause in report.as_ref().iter_reports() {
            if let Some(SideloadError::AuthWithMessage(code, message)) =
                cause.downcast_current_context::<SideloadError>()
                && *code == -21669
            {
                warn!("{} - {}", code, message);
                *last_error = format!("{} - {}", code, message).into();
                emit_post_two_factor_diagnostic(
                    sink,
                    PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyRejected {
                        apple_service_code: *code,
                    },
                );
                emit_post_two_factor_diagnostic(
                    sink,
                    PostTwoFactorDiagnosticEvent::TransitionToNeedsDevice2FAVerification,
                );
                return Ok(LoginState::NeedsDevice2FAVerification);
            }
        }
    }

    match res {
        Ok(_) => {
            emit_post_two_factor_diagnostic(
                sink,
                PostTwoFactorDiagnosticEvent::TrustedDeviceVerifySuccess,
            );
            emit_post_two_factor_diagnostic(
                sink,
                PostTwoFactorDiagnosticEvent::TransitionToNeedsLogin,
            );
            debug!("Trusted device 2FA completed, need to login again");
            Ok(LoginState::NeedsLogin)
        }
        Err(report) => {
            emit_post_two_factor_diagnostic(
                sink,
                PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyFailure {
                    result: post_two_factor_result_from_report(&report),
                },
            );
            Err(report)
        }
    }
}

fn classify_trusted_device_request<T>(
    result: Result<T, Report>,
    sink: Option<&PostTwoFactorDiagnosticSink>,
) -> Result<T, Report> {
    if let Err(report) = &result {
        emit_post_two_factor_diagnostic(
            sink,
            PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyFailure {
                result: post_two_factor_result_from_report(report),
            },
        );
    }
    result
}

fn classify_trusted_device_failure<T>(
    result: Result<T, Report>,
    sink: Option<&PostTwoFactorDiagnosticSink>,
    diagnostic_result: PostTwoFactorDiagnosticResult,
) -> Result<T, Report> {
    if result.is_err() {
        emit_post_two_factor_diagnostic(
            sink,
            PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyFailure {
                result: diagnostic_result,
            },
        );
    }
    result
}

impl AppleAccount {
    /// Create a new AppleAccountBuilder with the given email
    ///
    /// # Arguments
    /// - `email`: The Apple ID email address
    pub fn builder(email: &str) -> AppleAccountBuilder {
        AppleAccountBuilder::new(email)
    }

    /// Build the apple account with the given email
    ///
    /// Reccomended to use the AppleAccountBuilder instead
    /// # Arguments
    /// - `email`: The Apple ID email address
    /// - `anisette_provider`: The anisette provider to use
    /// - `debug`: DANGER, If true, accept invalid certificates and enable verbose connection
    pub async fn new(
        email: &str,
        anisette_generator: AnisetteDataGenerator,
        debug: bool,
        proxy_url: Option<String>,
    ) -> Result<Self, Report> {
        if debug {
            warn!("Debug mode enabled: this is a security risk!");
        }

        let client_info = anisette_generator
            .get_client_info()
            .await
            .context("Failed to get anisette client info")?;

        let grandslam_client = GrandSlam::new(client_info, debug, proxy_url.clone()).await?;

        Ok(AppleAccount {
            email: email.to_string(),
            spd: None,
            anisette_generator,
            grandslam_client: Arc::new(grandslam_client),
            debug,
            login_state: LoginState::NeedsLogin,
            trusted_phone_numbers: None,
            last_error: None,
            preflight_xcode_token: None,
        })
    }

    /// Log in to the Apple ID account
    /// # Arguments
    /// - `password`: The Apple ID password
    /// - `two_factor_callback`: A callback function that returns the two-factor authentication code
    /// # Errors
    /// Returns an error if the login fails
    #[cfg(target_arch = "wasm32")]
    pub async fn login<C, Fut>(
        &mut self,
        password: &str,
        two_factor_callback: C,
    ) -> Result<(), Report>
    where
        C: Fn(TwoFactorCallbackParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<TwoFactorCallbackResponse, Report>>,
    {
        self.login_impl(password, two_factor_callback, None).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn login<C, Fut>(
        &mut self,
        password: &str,
        two_factor_callback: C,
    ) -> Result<(), Report>
    where
        C: Fn(TwoFactorCallbackParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<TwoFactorCallbackResponse, Report>> + Send,
    {
        self.login_impl(password, two_factor_callback, None).await
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn login_with_diagnostics<C, Fut>(
        &mut self,
        password: &str,
        two_factor_callback: C,
        diagnostic_sink: PostTwoFactorDiagnosticSink,
    ) -> Result<(), Report>
    where
        C: Fn(TwoFactorCallbackParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<TwoFactorCallbackResponse, Report>>,
    {
        self.login_impl(password, two_factor_callback, Some(&diagnostic_sink))
            .await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn login_with_diagnostics<C, Fut>(
        &mut self,
        password: &str,
        two_factor_callback: C,
        diagnostic_sink: PostTwoFactorDiagnosticSink,
    ) -> Result<(), Report>
    where
        C: Fn(TwoFactorCallbackParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<TwoFactorCallbackResponse, Report>> + Send,
    {
        self.login_impl(password, two_factor_callback, Some(&diagnostic_sink))
            .await
    }

    async fn login_impl<C, Fut>(
        &mut self,
        password: &str,
        two_factor_callback: C,
        diagnostic_sink: Option<&PostTwoFactorDiagnosticSink>,
    ) -> Result<(), Report>
    where
        C: Fn(TwoFactorCallbackParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<TwoFactorCallbackResponse, Report>>,
    {
        info!("Logging in to Apple ID: {}", censor_email(&self.email));
        if self.debug {
            warn!("Debug mode enabled: this is a security risk!");
        }

        self.login_state = self
            .login_inner(password, diagnostic_sink)
            .await
            .context("Failed to log in to Apple ID")?;

        debug!("Initial login successful");

        let mut attempts = 0;

        loop {
            attempts += 1;
            if attempts > 15 {
                bail!(
                    "Couldn't login after 15 attempts, aborting (current state: {:?})",
                    self.login_state
                );
            }
            match self.login_state.clone() {
                LoginState::LoggedIn => {
                    if diagnostic_sink.is_some() && self.preflight_xcode_token.is_none() {
                        match self.get_app_token("xcode.auth").await {
                            Ok(token) => self.preflight_xcode_token = Some(token),
                            Err(report) if report_has_apple_service_code(&report, -22411) => {
                                emit_post_two_factor_diagnostic(
                                    diagnostic_sink,
                                    PostTwoFactorDiagnosticEvent::TransitionToNeedsDevice2FAVerification,
                                );
                                self.login_state = LoginState::NeedsDevice2FAVerification;
                                continue;
                            }
                            Err(report) => {
                                return Err(report
                                    .context("Failed to validate Xcode app token after login")
                                    .into_dynamic());
                            }
                        }
                    }
                    info!("Successfully logged in to Apple ID");
                    return Ok(());
                }
                LoginState::NeedsDevice2FA => {
                    if self.trusted_phone_numbers.is_none() {
                        self.trusted_phone_numbers = Some(self.get_trusted_numbers().await?);
                    }
                    self.send_trusted_device_2fa()
                        .await
                        .context("Failed to complete trusted device 2FA")?;
                    self.login_state = LoginState::NeedsDevice2FAVerification;
                }
                LoginState::NeedsDevice2FAVerification => {
                    let response = two_factor_callback(TwoFactorCallbackParams {
                        last_error: self.last_error.clone(),
                        unknown: false,
                        sms: false,
                        numbers: self.trusted_phone_numbers.clone().unwrap_or_default(),
                        selected_number_id: None,
                    })
                    .await?;
                    self.last_error = None;
                    match response {
                        TwoFactorCallbackResponse::SubmitCode(code) => {
                            self.login_state = self
                                .verify_trusted_device_2fa(code, diagnostic_sink)
                                .await
                                .context("Failed to verify trusted device 2FA")?;
                        }
                        TwoFactorCallbackResponse::SendSms(selected_number_id) => {
                            self.login_state = self.select_number(selected_number_id)?;
                        }
                        TwoFactorCallbackResponse::SendToDevices
                        | TwoFactorCallbackResponse::ResendCode => {
                            self.login_state = LoginState::NeedsDevice2FA;
                        }
                        TwoFactorCallbackResponse::Abort => {
                            bail!("No 2FA code provided, aborting")
                        }
                    }
                }
                LoginState::NeedsSMS2FA(id) => {
                    if self.trusted_phone_numbers.is_none() {
                        self.trusted_phone_numbers = Some(self.get_trusted_numbers().await?);
                    }
                    info!("SMS 2FA required");
                    self.login_state = self
                        .send_sms_2fa(id)
                        .await
                        .context("Failed to complete SMS 2FA")?;
                }
                LoginState::NeedsSMS2FAVerification(id) => {
                    let response = two_factor_callback(TwoFactorCallbackParams {
                        unknown: false,
                        last_error: self.last_error.clone(),
                        sms: true,
                        numbers: self.trusted_phone_numbers.clone().unwrap_or_default(),
                        selected_number_id: Some(id),
                    })
                    .await?;
                    self.last_error = None;
                    match response {
                        TwoFactorCallbackResponse::SubmitCode(code) => {
                            self.login_state = self
                                .verify_sms_2fa(code, id)
                                .await
                                .context("Failed to verify trusted device 2FA")?;
                        }
                        TwoFactorCallbackResponse::SendSms(selected_number_id) => {
                            self.login_state = self.select_number(selected_number_id)?;
                        }
                        TwoFactorCallbackResponse::ResendCode => {
                            self.login_state = LoginState::NeedsSMS2FA(id);
                        }
                        TwoFactorCallbackResponse::SendToDevices => {
                            self.login_state = LoginState::NeedsDevice2FA;
                        }
                        TwoFactorCallbackResponse::Abort => {
                            bail!("No 2FA code provided, aborting")
                        }
                    }
                }
                LoginState::NeedsExtraStep(s) => {
                    info!("Additional authentication step required: {}", s);
                    if self.get_pet().is_err() {
                        bail!("Additional authentication required: {}", s);
                    }
                    self.login_state = LoginState::LoggedIn;
                }
                LoginState::NeedsLogin => {
                    debug!("Logging in again...");
                    self.login_state = self
                        .login_inner(password, diagnostic_sink)
                        .await
                        .context("Failed to login again")?;
                }
                LoginState::NeedsUnknown2FA => {
                    info!(
                        "The most recently attempted 2FA Method failed, please try a different method."
                    );
                    let response = two_factor_callback(TwoFactorCallbackParams {
                        unknown: true,
                        last_error: self.last_error.clone(),
                        sms: false,
                        numbers: self.trusted_phone_numbers.clone().unwrap_or_default(),
                        selected_number_id: None,
                    })
                    .await?;
                    self.last_error = None;
                    match response {
                        TwoFactorCallbackResponse::SubmitCode(_) => {
                            bail!("Cannot submit code without knowing which method to use");
                        }
                        TwoFactorCallbackResponse::SendSms(selected_number_id) => {
                            self.login_state = self.select_number(selected_number_id)?;
                        }
                        TwoFactorCallbackResponse::SendToDevices => {
                            self.login_state = LoginState::NeedsDevice2FA;
                        }
                        TwoFactorCallbackResponse::ResendCode => {
                            bail!("Cannot resend code without knowing which method to use");
                        }
                        TwoFactorCallbackResponse::Abort => {
                            bail!("No 2FA method selected, aborting");
                        }
                    }
                }
            }
        }
    }

    /// Get the user's first and last name associated with the Apple ID
    pub fn get_name(&self) -> Result<(String, String), Report> {
        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD not available, cannot get name"))?;

        Ok((spd.get_string("fn")?, spd.get_string("ln")?))
    }

    fn get_pet(&self) -> Result<String, Report> {
        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD not available, cannot get pet"))?;

        let pet = spd
            .get_dict("t")?
            .get_dict("com.apple.gs.idms.pet")?
            .get_string("token")?;

        Ok(pet)
    }

    async fn send_trusted_device_2fa(&mut self) -> Result<(), Report> {
        debug!("Trusted device 2FA required");

        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let request_code_url = self
            .grandslam_client
            .get_url("trustedDeviceSecondaryAuth")?;

        self.grandslam_client
            .get(&request_code_url)?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .send()
            .await
            .context("Failed to request trusted device 2fa")?
            .error_for_status()
            .context("Trusted device 2FA request failed")?;

        info!("Trusted device 2FA request sent");

        Ok(())
    }

    async fn verify_trusted_device_2fa(
        &mut self,
        code: String,
        diagnostic_sink: Option<&PostTwoFactorDiagnosticSink>,
    ) -> Result<LoginState, Report> {
        emit_post_two_factor_diagnostic(
            diagnostic_sink,
            PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyBegin,
        );
        let anisette_data = classify_trusted_device_request(
            self.anisette_generator
                .get_anisette_data(self.grandslam_client.clone())
                .await
                .context("Failed to get anisette data for 2FA")
                .map_err(|report| report.into_dynamic()),
            diagnostic_sink,
        )?;

        let submit_code_url = classify_trusted_device_request(
            self.grandslam_client.get_url("validateCode"),
            diagnostic_sink,
        )?;

        let request = classify_trusted_device_request(
            self.grandslam_client.get(&submit_code_url),
            diagnostic_sink,
        )?;
        let headers = classify_trusted_device_request(
            self.build_2fa_headers(&anisette_data).await,
            diagnostic_sink,
        )?;

        let response = request
            .headers(headers)
            .header("security-code", code)
            .send()
            .await
            .context("Failed to submit trusted device 2FA code")
            .map_err(|report| report.into_dynamic());
        let response = classify_trusted_device_request(response, diagnostic_sink)?;
        let response = classify_trusted_device_request(
            response
                .error_for_status()
                .context("Trusted device 2FA code submission failed")
                .map_err(|report| report.into_dynamic()),
            diagnostic_sink,
        )?;
        let res = classify_trusted_device_failure(
            response
                .text()
                .await
                .context("Failed to read trusted device 2FA response text")
                .map_err(|report| report.into_dynamic()),
            diagnostic_sink,
            PostTwoFactorDiagnosticResult::ResponseBodyFailure,
        )?;

        let plist: Dictionary = classify_trusted_device_failure(
            plist::from_bytes(res.as_bytes())
                .context("Failed to parse trusted device response plist")
                .map_err(|report| report.into_dynamic()),
            diagnostic_sink,
            PostTwoFactorDiagnosticResult::PlistParseFailure,
        )?;
        let res = plist
            .check_grandslam_error()
            .context("Trusted device 2FA rejected")
            .map_err(|report| report.into_dynamic());
        classify_trusted_device_response(res, &mut self.last_error, diagnostic_sink)
    }

    async fn send_sms_2fa(&mut self, id: u32) -> Result<LoginState, Report> {
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        //let request_code_url = self.grandslam_client.get_url("secondaryAuth")?;

        // self.grandslam_client
        //     .get_sms(&request_code_url)?
        //     .headers(self.build_2fa_headers(&anisette_data).await?)
        //     .send()
        //     .await
        //     .context("Failed to request SMS 2FA")?
        //     .error_for_status()
        //     .context("SMS 2FA request failed")?;

        let send_body = serde_json::json!({
            "phoneNumber": {
                "id": id
            },
            "mode": "sms"
        });

        let res = self
            .grandslam_client
            .put_sms("https://gsa.apple.com/auth/verify/phone")?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .body(send_body.to_string())
            .send()
            .await
            .context("Failed to request SMS 2FA")?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res
                .text()
                .await
                .context("Failed to read SMS 2FA error response text")?;
            // try to parse as json, if it fails, just bail with the text
            let error = Self::parse_sms_error(text, status.as_u16())?;

            if error.code == "-28248" {
                // Verification codes can’t be sent to this phone number at this time. Please try again later.
                warn!("{} - {}", error.title, error.message);
                self.last_error = format!("{} - {}", error.title, error.message).into();
                return Ok(LoginState::NeedsUnknown2FA);
            }

            if error.code == "-22979" {
                // Too many verification codes have been sent. - Enter the last code you received or try again later.
                warn!("{} - {}", error.title, error.message);
                self.last_error = format!("{} - {}", error.title, error.message).into();
                return Ok(LoginState::NeedsUnknown2FA);
            }

            if error.code == "-22981" {
                // Too many verification codes have been sent. - Enter the last code you received or try again later.
                // Not sure why there are two identical errors with different codes
                warn!("{} - {}", error.title, error.message);
                self.last_error = format!("{} - {}", error.title, error.message).into();
                return Ok(LoginState::NeedsUnknown2FA);
            }

            bail!(
                "SMS 2FA request failed (code {}): {} - {}",
                error.code,
                error.title,
                error.message
            );
        };

        info!("SMS 2FA request sent");

        Ok(LoginState::NeedsSMS2FAVerification(id))
    }

    async fn verify_sms_2fa(&mut self, code: String, id: u32) -> Result<LoginState, Report> {
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let body = serde_json::json!({
            "securityCode": {
                "code": code
            },
            "phoneNumber": {
                "id": id
            },
            "mode": "sms"
        });

        let res = self
            .grandslam_client
            .post_sms("https://gsa.apple.com/auth/verify/phone/securitycode")?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .body(body.to_string())
            .send()
            .await
            .context("Failed to submit SMS 2FA code")?;

        let status = res.status();
        let text = res
            .text()
            .await
            .context("Failed to read SMS 2FA error response text")?;
        if !status.is_success() {
            // try to parse as json, if it fails, just bail with the text
            let error = Self::parse_sms_error(text, status.as_u16())?;

            if error.code == "-21669" {
                // Incorrect Verification Code, let the user try again
                warn!("{} - {}", error.title, error.message);
                self.last_error = format!("{} - {}", error.title, error.message).into();
                return Ok(LoginState::NeedsSMS2FAVerification(id));
            }

            bail!(
                "SMS 2FA code submission failed (code {}): {} - {}",
                error.code,
                error.title,
                error.message
            );
        };

        debug!("SMS 2FA completed, need to login again");
        Ok(LoginState::NeedsLogin)
    }

    fn parse_sms_error(text: String, status: u16) -> Result<SMSTwoFactorError, Report> {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(service_errors) = json.get("serviceErrors")
            && let Some(first_error) = service_errors.as_array().and_then(|arr| arr.first())
        {
            let code = first_error
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("unknown");
            let title = first_error
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("No title provided");
            let message = first_error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("No message provided");

            return Ok(SMSTwoFactorError {
                code: code.to_string(),
                title: title.to_string(),
                message: message.to_string(),
            });
        }
        bail!(
            "SMS 2FA code submission failed with http status {}: {}",
            status,
            text
        );
    }

    async fn get_trusted_numbers(&mut self) -> Result<Vec<TrustedNumber>, Report> {
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let res = self
            .grandslam_client
            .get_sms("https://gsa.apple.com/auth")?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .send()
            .await?;

        let status = res.status().as_u16();
        let text = res
            .text()
            .await
            .context("Failed to read SMS 2FA error response text")?;
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(numbers) = json.get("trustedPhoneNumbers")
        {
            let numbers: Vec<TrustedNumber> = serde_json::from_value(numbers.clone())
                .context("Failed to parse trusted phone numbers")?;
            debug!(
                "Retrieved {} trusted phone numbers (status {}): {:?}",
                numbers.len(),
                status,
                numbers
            );
            return Ok(numbers);
        }

        bail!(
            "Failed to retrieve trusted phone numbers (status {}): {}",
            status,
            text
        );
    }

    fn select_number(&self, selected_number_id: u32) -> Result<LoginState, Report> {
        let numbers = self.trusted_phone_numbers.clone().unwrap_or_default();
        if let Some(number) = numbers.iter().find(|n| n.id == selected_number_id) {
            debug!("Selected trusted number: {}", number.number_with_dial_code);
            return Ok(LoginState::NeedsSMS2FA(number.id));
        }
        bail!("Selected trusted number ID not found in trusted numbers");
    }

    async fn build_2fa_headers(&self, anisette_data: &AnisetteData) -> Result<HeaderMap, Report> {
        let mut headers = anisette_data.get_header_map()?;

        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD data not available, cannot build 2FA headers"))?;

        let adsid = spd
            .get_str("adsid")
            .context("Failed to build 2FA headers")?;
        let token = spd
            .get_str("GsIdmsToken")
            .context("Failed to build 2FA headers")?;
        let identity = BASE64_STANDARD.encode(format!("{}:{}", adsid, token));

        headers.insert(
            "X-Apple-Identity-Token",
            reqwest::header::HeaderValue::from_str(&identity)?,
        );
        headers.insert(
            "X-Apple-I-MD-RINFO",
            reqwest::header::HeaderValue::from_str(&anisette_data.routing_info)?,
        );

        Ok(headers)
    }

    async fn login_inner(
        &mut self,
        password: &str,
        diagnostic_sink: Option<&PostTwoFactorDiagnosticSink>,
    ) -> Result<LoginState, Report> {
        emit_post_two_factor_login_begin(PostTwoFactorLoginStage::InitialLogin, diagnostic_sink);
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for login")?;

        let gs_service_url = self.grandslam_client.get_url("gsService")?;
        debug!("GrandSlam service URL: {}", gs_service_url);

        let mut cpd = anisette_data.get_client_provided_data();

        let srp_client = srp::Client::<G2048, Sha256>::new_with_options(false);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let req1 = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "A2k": a_pub.clone(), // A2k = client public ephemeral
                "cpd": cpd.clone(), // cpd = client provided data
                "o": "init", // o = operation
                "ps": [ // ps = protocols supported
                    "s2k",
                    "s2k_fo"
                ],
                "u": self.email.clone(), // u = username
            }
        });

        debug!("Sending initial login request");

        let mut raw_response = self
            .grandslam_client
            .plist_request(&gs_service_url, &req1, None)
            .await;

        if let Ok(response) = &raw_response
            && let Some(sim) = resync_sim(response)
        {
            debug!("Anisette resync required (hsc 434); syncing then retrying init");
            let fresh_anisette = self
                .anisette_generator
                .resync(&sim)
                .await
                .context("Anisette resync failed")?;
            cpd = fresh_anisette.get_client_provided_data();
            let resynced_request = plist!(dict {
                "Header": {
                    "Version": "1.0.1"
                },
                "Request": {
                    "A2k": a_pub,
                    "cpd": cpd.clone(),
                    "o": "init",
                    "ps": [
                        "s2k",
                        "s2k_fo"
                    ],
                    "u": self.email.clone(),
                }
            });
            raw_response = self
                .grandslam_client
                .plist_request(&gs_service_url, &resynced_request, None)
                .await;
        }

        let response = classify_login_response(
            PostTwoFactorLoginStage::InitialLogin,
            raw_response,
            diagnostic_sink,
            "Failed to send initial login request",
            "GrandSlam error during initial login request",
        )?;

        debug!("Login step 1 completed");

        let salt = response
            .get_data("s")
            .context("Failed to parse initial login response")?;
        let b_pub = response
            .get_data("B")
            .context("Failed to parse initial login response")?;
        let iters = response
            .get_signed_integer("i")
            .context("Failed to parse initial login response")?;
        let c = response
            .get_str("c")
            .context("Failed to parse initial login response")?;
        let selected_protocol = response
            .get_str("sp")
            .context("Failed to parse initial login response")?;

        debug!(
            "Selected SRP protocol: {}, iterations: {}",
            selected_protocol, iters
        );

        if selected_protocol != "s2k" && selected_protocol != "s2k_fo" {
            bail!("Unsupported SRP protocol selected: {}", selected_protocol);
        }

        let hashed_password = Sha256::digest(password.as_bytes());

        let password_hash = if selected_protocol == "s2k_fo" {
            hex::encode(hashed_password).into_bytes()
        } else {
            hashed_password.to_vec()
        };

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(&password_hash, salt, iters as u32, &mut password_buf)
            .context("Failed to derive password using PBKDF2")?;

        let verifier = srp_client
            .process_reply(&a, self.email.as_bytes(), &password_buf, salt, b_pub)
            .context("Failed to compute SRP proof")?;

        let req2 = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "M1": verifier.proof().to_vec(), // A2k = client public ephemeral
                "c": c, // c = client proof from step 1
                "cpd": cpd, // cpd = client provided data
                "o": "complete", // o = operation
                "u": self.email.clone(), // u = username
            }
        });

        let mut close_headers = HeaderMap::new();
        close_headers.insert("Connection", HeaderValue::from_static("close"));

        emit_post_two_factor_login_begin(PostTwoFactorLoginStage::ProofLogin, diagnostic_sink);

        let response2 = classify_login_response(
            PostTwoFactorLoginStage::ProofLogin,
            self.grandslam_client
                .plist_request(&gs_service_url, &req2, Some(close_headers))
                .await,
            diagnostic_sink,
            "Failed to send proof login request",
            "GrandSlam error during proof login request",
        )?;

        debug!("Login step 2 response received, verifying server proof");

        let m2 = response2
            .get_data("M2")
            .context("Failed to parse proof login response")?;
        verifier
            .verify_server(m2)
            .map_err(|e| report!("Negotiation failed, server proof mismatch: {}", e))?;

        debug!("Server proof verified");

        let spd_encrypted = response2
            .get_data("spd")
            .context("Failed to get SPD from login response")?;

        let spd_decrypted = Self::decrypt_cbc(&verifier, spd_encrypted)
            .context("Failed to decrypt SPD from login response")?;
        let spd: plist::Dictionary =
            plist::from_bytes(&spd_decrypted).context("Failed to parse decrypted SPD plist")?;

        self.spd = Some(spd);

        let status = response2
            .get_dict("Status")
            .context("Failed to parse proof login response")?;

        debug!("Login step 2 completed");

        Ok(classify_post_two_factor_login_state(
            status,
            diagnostic_sink,
        ))
    }

    pub async fn get_app_token(&mut self, app: &str) -> Result<AppToken, Report> {
        let app = if app.contains("com.apple.gs.") {
            app.to_string()
        } else {
            format!("com.apple.gs.{}", app)
        };

        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for login")?;

        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD data not available, cannot get app token"))?;

        let dsid = spd.get_str("adsid").context("Failed to get app token")?;
        let auth_token = spd
            .get_str("GsIdmsToken")
            .context("Failed to get app token")?;
        let session_key = spd.get_data("sk").context("Failed to get app token")?;
        let c = spd.get_data("c").context("Failed to get app token")?;

        let checksum = Hmac::<Sha256>::new_from_slice(session_key)
            .context("Failed to create HMAC for app token checksum")
            .attach_with(|| SensitivePlistAttachment::new(spd.clone()))?
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec();

        let gs_service_url = self.grandslam_client.get_url("gsService")?;
        let cpd = anisette_data.get_client_provided_data();

        let request = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "app": [app.clone()],
                "c": c,
                "checksum": checksum,
                "cpd": cpd,
                "o": "apptokens",
                "u": dsid,
                "t": auth_token
            }
        });

        let resp = self
            .grandslam_client
            .plist_request(&gs_service_url, &request, None)
            .await
            .context("Failed to send app token request")?
            .check_grandslam_error()
            .context("GrandSlam error during app token request")?;

        let encrypted_token = resp
            .get_data("et")
            .context("Failed to get encrypted token")?;

        debug!("Acquired encrypted token for {}", app);
        let decrypted_token = Self::decrypt_gcm(encrypted_token, session_key)
            .context("Failed to decrypt app token")?;
        debug!("Decrypted app token for {}", app);

        let token: Dictionary = plist::from_bytes(&decrypted_token)
            .context("Failed to parse decrypted app token plist")?;

        let status = token
            .get_signed_integer("status-code")
            .context("Failed to get status code from app token")?;
        if status != 200 {
            bail!("App token request failed with status code {}", status);
        }
        let token_dict = token
            .get_dict("t")
            .context("Failed to get token dictionary from app token")?;
        let app_token = token_dict
            .get_dict(&app)
            .context("Failed to get app token string")?;

        let app_token = AppToken {
            token: app_token
                .get_str("token")
                .context("Failed to get app token string")?
                .to_string(),
            duration: app_token
                .get_signed_integer("duration")
                .context("Failed to get app token duration")? as u64,
            expiry: app_token
                .get_signed_integer("expiry")
                .context("Failed to get app token expiry")? as u64,
        };

        info!("Successfully retrieved app token for {}", app);

        Ok(app_token)
    }

    pub async fn get_xcode_app_token(&mut self) -> Result<AppToken, Report> {
        if let Some(token) = self.preflight_xcode_token.take() {
            return Ok(token);
        }
        self.get_app_token("xcode.auth").await
    }

    fn create_session_key(usr: &ClientVerifier<Sha256>, name: &str) -> Result<Vec<u8>, Report> {
        Ok(Hmac::<Sha256>::new_from_slice(usr.key())?
            .chain_update(name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec())
    }

    fn decrypt_cbc(usr: &ClientVerifier<Sha256>, data: &[u8]) -> Result<Vec<u8>, Report> {
        let extra_data_key = Self::create_session_key(usr, "extra data key:")?;
        let extra_data_iv = Self::create_session_key(usr, "extra data iv:")?;
        let extra_data_iv = &extra_data_iv[..16];

        Ok(
            cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)?
                .decrypt_padded_vec::<Pkcs7>(data)?,
        )
    }

    fn decrypt_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Report> {
        if data.len() < 3 + 16 + 16 {
            bail!(
                "Encrypted token is too short to be valid (only {} bytes)",
                data.len()
            );
        }
        let header = &data[0..3];
        if header != b"XYZ" {
            bail!(
                "Encrypted token is in an unknown format: {}",
                String::from_utf8_lossy(header)
            );
        }
        let iv = &data[3..19];
        let ciphertext_and_tag = &data[19..];

        if key.len() != 32 {
            bail!("Session key is not the correct length: {} bytes", key.len());
        }
        if iv.len() != 16 {
            bail!("IV is not the correct length: {} bytes", iv.len());
        }

        debug!(
            "Decrypting GCM data with key of length {} and IV of length {}",
            key.len(),
            iv.len()
        );
        let key = aes_gcm::Key::<AesGcm<Aes256, U16>>::try_from(key)?;
        debug!("GCM key created successfully");
        let cipher = AesGcm::<Aes256, U16>::new(&key);
        debug!("GCM cipher initialized successfully");
        let nonce = Nonce::<U16>::try_from(iv)?;
        debug!("GCM nonce created successfully");

        let mut buf = ciphertext_and_tag.to_vec();

        cipher
            .decrypt_in_place(&nonce, header, &mut buf)
            .map_err(|e| report!("Failed to decrypt gcm: {}", e))?;
        debug!("GCM decryption successful");

        Ok(buf)
    }
}

impl std::fmt::Display for AppleAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Apple Account: ")?;
        match self.get_name() {
            Ok((first, last)) => write!(f, "{} {} ", first, last),
            Err(_) => Ok(()),
        }?;
        write!(f, "{} ({:?})", self.email, self.login_state)
    }
}

#[derive(Debug, Clone)]
pub struct AppToken {
    pub token: String,
    pub duration: u64,
    pub expiry: u64,
}

fn censor_email(email: &str) -> String {
    if std::env::var("DEBUG_SENSITIVE").is_ok() {
        return email.to_string();
    }
    if let Some(at_pos) = email.find('@') {
        let (local, domain) = email.split_at(at_pos);
        if local.len() <= 2 {
            format!("{}***{}", &local[0..1], &domain)
        } else {
            format!(
                "{}***{}{}",
                &local[0..1],
                &local[local.len() - 1..],
                &domain
            )
        }
    } else {
        "***".to_string()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_device_response(code: Option<i64>) -> Result<Dictionary, Report> {
        let mut response = Dictionary::new();
        if let Some(code) = code {
            let mut status = Dictionary::new();
            status.insert("ec".into(), plist::Value::Integer(code.into()));
            status.insert(
                "em".into(),
                plist::Value::String("test trusted-device failure".into()),
            );
            response.insert("Status".into(), plist::Value::Dictionary(status));
        }
        response
            .check_grandslam_error()
            .map_err(|report| report.into_dynamic())
    }

    fn diagnostic_sink() -> (
        PostTwoFactorDiagnosticSink,
        Arc<tokio::sync::Mutex<Vec<PostTwoFactorDiagnosticEvent>>>,
    ) {
        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let sink: PostTwoFactorDiagnosticSink = Arc::new(move |event| {
            sink_events
                .try_lock()
                .expect("diagnostic test history is not locked")
                .push(event);
        });
        (sink, events)
    }

    #[test]
    fn xcode_token_minus_22411_requires_deferred_trusted_device_verification() {
        let report = Report::new(SideloadError::AuthWithMessage(
            -22411,
            "test two-factor requirement".into(),
        ))
        .into_dynamic();
        assert!(report_has_apple_service_code(&report, -22411));
        assert!(!report_has_apple_service_code(&report, -22406));
    }

    #[test]
    fn unrelated_failures_do_not_trigger_deferred_trusted_device_verification() {
        let report = Report::new(std::io::Error::other("test transport failure")).into_dynamic();
        assert!(!report_has_apple_service_code(&report, -22411));
    }

    #[test]
    fn trusted_device_success_reports_login_transition() {
        let (sink, events) = diagnostic_sink();
        let mut last_error = None;
        let state = classify_trusted_device_response(
            trusted_device_response(None),
            &mut last_error,
            Some(&sink),
        )
        .expect("trusted-device success should classify");

        assert!(matches!(state, LoginState::NeedsLogin));
        assert!(last_error.is_none());
        assert_eq!(
            *events
                .try_lock()
                .expect("diagnostic test history is not locked"),
            vec![
                PostTwoFactorDiagnosticEvent::TrustedDeviceVerifySuccess,
                PostTwoFactorDiagnosticEvent::TransitionToNeedsLogin,
            ]
        );
    }

    #[test]
    fn trusted_device_incorrect_code_reports_retry_state_without_resubmission() {
        let (sink, events) = diagnostic_sink();
        let mut last_error = None;
        let state = classify_trusted_device_response(
            trusted_device_response(Some(-21669)),
            &mut last_error,
            Some(&sink),
        )
        .expect("incorrect trusted-device code should classify");

        assert!(matches!(state, LoginState::NeedsDevice2FAVerification));
        assert_eq!(
            last_error.as_deref(),
            Some("-21669 - test trusted-device failure")
        );
        assert_eq!(
            *events
                .try_lock()
                .expect("diagnostic test history is not locked"),
            vec![
                PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyRejected {
                    apple_service_code: -21669,
                },
                PostTwoFactorDiagnosticEvent::TransitionToNeedsDevice2FAVerification,
            ]
        );
    }

    #[test]
    fn trusted_device_other_failure_reports_typed_terminal_result() {
        let (sink, events) = diagnostic_sink();
        let mut last_error = None;
        let result = classify_trusted_device_response(
            trusted_device_response(Some(-22406)),
            &mut last_error,
            Some(&sink),
        );

        assert!(result.is_err());
        assert!(last_error.is_none());
        assert_eq!(
            *events
                .try_lock()
                .expect("diagnostic test history is not locked"),
            vec![PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyFailure {
                result: PostTwoFactorDiagnosticResult::AppleServiceCode(-22406),
            }]
        );
    }

    #[test]
    fn post_two_factor_request_stages_report_success_and_http_failure() {
        let (sink, events) = diagnostic_sink();
        emit_post_two_factor_login_begin(PostTwoFactorLoginStage::InitialLogin, Some(&sink));
        let initial = classify_login_response(
            PostTwoFactorLoginStage::InitialLogin,
            Ok(Dictionary::new()),
            Some(&sink),
            "initial request failed",
            "initial response failed",
        )
        .expect("initial login response should classify");

        emit_post_two_factor_login_begin(PostTwoFactorLoginStage::ProofLogin, Some(&sink));
        emit_post_two_factor_login_response_result(
            PostTwoFactorLoginStage::ProofLogin,
            PostTwoFactorDiagnosticResult::HttpStatus(503),
            Some(&sink),
        );

        assert!(initial.is_empty());
        assert_eq!(
            *events
                .try_lock()
                .expect("diagnostic test history is not locked"),
            vec![
                PostTwoFactorDiagnosticEvent::PostTwoFactorInitialLoginBegin,
                PostTwoFactorDiagnosticEvent::PostTwoFactorInitialLoginResponseResult {
                    result: PostTwoFactorDiagnosticResult::Success,
                },
                PostTwoFactorDiagnosticEvent::PostTwoFactorProofLoginBegin,
                PostTwoFactorDiagnosticEvent::PostTwoFactorProofLoginResponseResult {
                    result: PostTwoFactorDiagnosticResult::HttpStatus(503),
                },
            ]
        );
    }

    #[test]
    fn post_login_two_factor_response_reports_callback_reentry() {
        let (sink, events) = diagnostic_sink();
        let mut status = Dictionary::new();
        status.insert(
            "au".into(),
            plist::Value::String("trustedDeviceSecondaryAuth".into()),
        );

        let state = classify_post_two_factor_login_state(&status, Some(&sink));

        assert!(matches!(state, LoginState::NeedsDevice2FA));
        assert_eq!(
            *events
                .try_lock()
                .expect("diagnostic test history is not locked"),
            vec![PostTwoFactorDiagnosticEvent::TransitionToNeedsDevice2FA {
                preceding_stage: PostTwoFactorLoginStage::ProofLogin,
            }]
        );
    }

    #[test]
    fn trusted_device_body_and_plist_failures_report_distinct_results() {
        let (sink, events) = diagnostic_sink();
        let body_error: Result<(), Report> =
            Err(Report::new(std::io::Error::other("response body failed")).into_dynamic());
        let plist_error: Result<(), Report> =
            Err(Report::new(std::io::Error::other("plist parse failed")).into_dynamic());

        assert!(
            classify_trusted_device_failure(
                body_error,
                Some(&sink),
                PostTwoFactorDiagnosticResult::ResponseBodyFailure,
            )
            .is_err()
        );
        assert!(
            classify_trusted_device_failure(
                plist_error,
                Some(&sink),
                PostTwoFactorDiagnosticResult::PlistParseFailure,
            )
            .is_err()
        );
        assert_eq!(
            *events
                .try_lock()
                .expect("diagnostic test history is not locked"),
            vec![
                PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyFailure {
                    result: PostTwoFactorDiagnosticResult::ResponseBodyFailure,
                },
                PostTwoFactorDiagnosticEvent::TrustedDeviceVerifyFailure {
                    result: PostTwoFactorDiagnosticResult::PlistParseFailure,
                },
            ]
        );
    }

    #[test]
    fn anisette_resync_extracts_only_hsc_434_sim() {
        let mut status = Dictionary::new();
        status.insert("hsc".into(), plist::Value::Integer(434.into()));
        status.insert(
            "X-Apple-I-MD-DATA".into(),
            plist::Value::Data(vec![0x01, 0x02, 0x03]),
        );
        let mut response = Dictionary::new();
        response.insert("Status".into(), plist::Value::Dictionary(status));

        assert_eq!(resync_sim(&response).as_deref(), Some("AQID"));

        response
            .get_mut("Status")
            .and_then(plist::Value::as_dictionary_mut)
            .expect("status dictionary")
            .insert("hsc".into(), plist::Value::Integer(200.into()));
        assert_eq!(resync_sim(&response), None);
    }
}
