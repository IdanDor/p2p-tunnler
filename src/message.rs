use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub timestamp: std::time::SystemTime,
    pub ip_addr_list: Vec<std::net::SocketAddr>,
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
        };

        assert_eq!(
            serde_json::to_string(&message).unwrap(),
            r#"{"timestamp":{"secs_since_epoch":1234567890,"nanos_since_epoch":123456789},"ip_addr_list":["192.0.2.10:1025","[2001:db8::10]:65535"]}"#
        );
    }
}
