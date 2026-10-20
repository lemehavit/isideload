use plist::{Dictionary, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeveloperDeviceType {
    Any,
    Ios,
    Tvos,
    Watchos,
}

impl DeveloperDeviceType {
    pub fn url_segment(&self) -> &'static str {
        match self {
            DeveloperDeviceType::Any => "",
            DeveloperDeviceType::Ios => "ios/",
            // Xcode-compatible clients send tvOS requests to the iOS endpoints
            // and mark the platform in the body instead (see `platform_fields`).
            DeveloperDeviceType::Tvos => "ios/",
            DeveloperDeviceType::Watchos => "watchos/",
        }
    }

    /// Extra request body fields that select a non-iOS platform on the iOS
    /// endpoints. Only `addDevice` and `downloadTeamProvisioningProfile` need them.
    pub fn platform_fields(&self) -> Dictionary {
        let mut fields = Dictionary::new();
        if let DeveloperDeviceType::Tvos = self {
            fields.insert("DTDK_Platform".into(), Value::String("tvos".into()));
            fields.insert("subPlatform".into(), Value::String("tvOS".into()));
        }
        fields
    }
}

/// Platform fields for an optional device type; empty for iOS and `None`.
pub fn platform_fields(device_type: &Option<DeveloperDeviceType>) -> Dictionary {
    device_type
        .as_ref()
        .map(DeveloperDeviceType::platform_fields)
        .unwrap_or_default()
}

pub fn dev_url(endpoint: &str, device_type: impl Into<Option<DeveloperDeviceType>>) -> String {
    format!(
        "https://developerservices2.apple.com/services/QH65B2/{}{}.action?clientId=XABBG36SBA",
        device_type
            .into()
            .unwrap_or(DeveloperDeviceType::Ios)
            .url_segment(),
        endpoint,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tvos_uses_ios_endpoint_with_platform_fields() {
        assert_eq!(
            dev_url("addDevice", DeveloperDeviceType::Tvos),
            dev_url("addDevice", DeveloperDeviceType::Ios)
        );
        let fields = platform_fields(&Some(DeveloperDeviceType::Tvos));
        assert_eq!(
            fields.get("DTDK_Platform").and_then(Value::as_string),
            Some("tvos")
        );
        assert_eq!(
            fields.get("subPlatform").and_then(Value::as_string),
            Some("tvOS")
        );
    }

    #[test]
    fn ios_and_default_add_no_platform_fields() {
        assert!(platform_fields(&None).is_empty());
        assert!(platform_fields(&Some(DeveloperDeviceType::Ios)).is_empty());
    }
}
