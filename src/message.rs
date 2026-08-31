use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Message {
    pub timestamp: std::time::SystemTime,
    pub ip_addr_list: Vec<std::net::SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<Control>,
}

/// Optional, forward-compatible control-plane metadata.  The string is kept
/// as Base64 in the DHT JSON so the legacy address record remains readable by
/// older peers that ignore unknown fields.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Control {
    pub probe_token: String,
}

#[cfg(test)]
mod tests {
    use super::Message;
    use std::time::{Duration, SystemTime};

    #[test]
    fn serializes_the_legacy_dht_message_shape() {
        let message = Message {
            timestamp: SystemTime::UNIX_EPOCH + Duration::new(1_234_567_890, 123_456_789),
            ip_addr_list: vec![
                "192.0.2.10:1025".parse().unwrap(),
                "[2001:db8::10]:65535".parse().unwrap(),
            ],
            control: None,
        };

        assert_eq!(
            serde_json::to_string(&message).unwrap(),
            r#"{"timestamp":{"secs_since_epoch":1234567890,"nanos_since_epoch":123456789},"ip_addr_list":["192.0.2.10:1025","[2001:db8::10]:65535"]}"#
        );
    }

    #[test]
    fn legacy_decoder_ignores_the_control_extension() {
        #[derive(serde::Deserialize)]
        struct LegacyMessage {
            timestamp: SystemTime,
            ip_addr_list: Vec<std::net::SocketAddr>,
        }

        let decoded: LegacyMessage = serde_json::from_str(
            r#"{"timestamp":{"secs_since_epoch":1,"nanos_since_epoch":0},"ip_addr_list":["192.0.2.10:1025"],"control":{"probe_token":"AAAAAAAAAAAAAAAAAAAAAA=="}}"#,
        )
        .unwrap();
        assert_eq!(
            decoded.timestamp,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1)
        );
        assert_eq!(
            decoded.ip_addr_list,
            vec!["192.0.2.10:1025".parse().unwrap()]
        );
    }
}
