//! analyzer for tcp/tls

use std::sync::{Arc, RwLock};

use bytes::BytesMut;
use tracing::debug;

use crate::*;

/// TLSAnalyzer is an analyzer for TLS protocol.
#[derive(Debug, Default)]
pub struct TLSAnalyzer {}

impl TLSAnalyzer {
    /// Construct a empty HTTPAnalyzer.
    pub fn new() -> Self {
        Self {}
    }
}

impl Analyzer for TLSAnalyzer {
    fn name(&self) -> &str {
        "tls"
    }

    fn limit(&self) -> i32 {
        8192
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TCPAnalyzer for TLSAnalyzer {
    #[allow(unused_variables)]
    fn new_tcp(&self, info: TCPInfo) -> Box<dyn TCPStream> {
        debug!("Creating a new tls analyzer");
        Box::new(TLSStream::new())
    }
}

/// TLSStream is a stream for TLS protocol.
pub struct TLSStream {
    req_buf: BytesMut,
    req_map: PropMap,
    req_updated: bool,
    req_lsm: Arc<RwLock<utils::lsm::LinearStateMachine<TLSStream>>>,
    req_done: bool,

    resp_buf: BytesMut,
    resp_map: PropMap,
    resp_updated: bool,
    resp_lsm: Arc<RwLock<utils::lsm::LinearStateMachine<TLSStream>>>,
    resp_done: bool,

    client_hello_len: i32,
    server_hello_len: i32,
}

impl TLSStream {
    fn new() -> Self {
        Self {
            req_buf: BytesMut::new(),
            req_map: PropMap::new(),
            req_updated: false,
            req_lsm: Arc::new(RwLock::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.tls_client_hello_preprocess()),
                Box::new(|s| s.parse_client_hello_data()),
            ]))),
            req_done: false,

            resp_buf: BytesMut::new(),
            resp_map: PropMap::new(),
            resp_updated: false,
            resp_lsm: Arc::new(RwLock::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.tls_server_hello_preprocess()),
                Box::new(|s| s.parse_server_hello_data()),
            ]))),
            resp_done: false,
            client_hello_len: 0,
            server_hello_len: 0,
        }
    }

    // tls_client_hello_preprocess validates ClientHello message.
    //
    // During validation, message header and first handshake header may be removed
    // from `self.req_buf`.
    fn tls_client_hello_preprocess(&mut self) -> utils::lsm::LSMAction {
        // headers size: content type (1 byte) + legacy protocol version (2 bytes) +
        //   + content length (2 bytes) + message type (1 byte) +
        //   + handshake length (3 bytes)
        const HEADERS_SIZE: usize = 9;

        // minimal data size: protocol version (2 bytes) + random (32 bytes) +
        //   + session ID (1 byte) + cipher suites (4 bytes) +
        //   + compression methods (2 bytes) + no extensions
        const MIN_DATA_SIZE: i32 = 41;

        if self.req_buf.len() >= HEADERS_SIZE {
            let header = self.req_buf.split_to(HEADERS_SIZE);
            if header[0] != tls::RECORD_TYPE_HANDSHAKE || header[5] != tls::TYPE_CLIENT_HELLO {
                return utils::lsm::LSMAction::Cancel;
            }

            self.client_hello_len =
                (header[6] as i32) << 16 | (header[7] as i32) << 8 | (header[8] as i32);
            if self.client_hello_len < MIN_DATA_SIZE {
                return utils::lsm::LSMAction::Cancel;
            }

            // TODO: something is missing. See:
            //   const messageHeaderSize = 4
            //   fullMessageLen := int(header3)<<8 | int(header4)
            //   msgNo := fullMessageLen / int(messageHeaderSize+self.serverHelloLen)
            //   if msgNo != 1 {
            //     // what here?
            //   }
            //   if messageNo != int(messageNo) {
            //     // what here?
            //   }

            utils::lsm::LSMAction::Next
        } else {
            // not a full header yet
            utils::lsm::LSMAction::Pause
        }
    }

    // parse_client_hello_data converts valid ClientHello message data (without
    // headers) into `analyzer.PropMap`.
    //
    // Parsing error may leave `s.req_buf` in an unusable state.
    fn parse_client_hello_data(&mut self) -> utils::lsm::LSMAction {
        if self.client_hello_len as usize <= self.req_buf.len() {
            let mut ch_buf = self.req_buf.split_to(self.client_hello_len as usize);
            if let Some(m) = tls::parse_tls_client_hello_msg_data(&mut ch_buf) {
                self.req_updated = true;
                self.req_map = m;
                utils::lsm::LSMAction::Next
            } else {
                utils::lsm::LSMAction::Cancel
            }
        } else {
            // Not a full client hello yet
            utils::lsm::LSMAction::Pause
        }
    }

    fn tls_server_hello_preprocess(&mut self) -> utils::lsm::LSMAction {
        // header size: content type (1 byte) + legacy protocol version (2 byte) +
        //   + content length (2 byte) + message type (1 byte) +
        //   + handshake length (3 byte)
        const HEADERS_SIZE: usize = 9;

        // minimal data size: server version (2 byte) + random (32 byte) +
        //   + session ID (>=1 byte) + cipher suite (2 byte) +
        //   + compression method (1 byte) + no extensions
        const MIN_DATA_SIZE: i32 = 38;

        if self.resp_buf.len() >= HEADERS_SIZE {
            let header = self.resp_buf.split_to(HEADERS_SIZE);
            if header[0] != tls::RECORD_TYPE_HANDSHAKE || header[5] != tls::TYPE_SERVER_HELLO {
                return utils::lsm::LSMAction::Cancel;
            }

            self.server_hello_len =
                (header[6] as i32) << 16 | (header[7] as i32) << 8 | (header[8] as i32);
            if self.server_hello_len < MIN_DATA_SIZE {
                return utils::lsm::LSMAction::Cancel;
            }

            // TODO: something is missing. See example:
            //   const messageHeaderSize = 4
            //   fullMessageLen := int(header[3])<<8 | int(header[4])
            //   msgNo := fullMessageLen / int(messageHeaderSize+self.serverHelloLen)
            //   if msgNo != 1 {
            //     // what here?
            //   }
            //   if messageNo != int(messageNo) {
            //     // what here?
            //   }

            utils::lsm::LSMAction::Next
        } else {
            // not a full header yet
            utils::lsm::LSMAction::Pause
        }
    }

    fn parse_server_hello_data(&mut self) -> utils::lsm::LSMAction {
        if self.server_hello_len as usize <= self.resp_buf.len() {
            let mut sh_buf = self.resp_buf.split_to(self.server_hello_len as usize);
            if let Some(m) = tls::parse_tls_server_hello_msg_data(&mut sh_buf) {
                self.resp_updated = true;
                self.resp_map = m;
                utils::lsm::LSMAction::Next
            } else {
                utils::lsm::LSMAction::Cancel
            }
        } else {
            // Not a full server hello yet
            utils::lsm::LSMAction::Pause
        }
    }
}

impl TCPStream for TLSStream {
    #[allow(unused_variables)]
    fn feed(
        &mut self,
        rev: bool,
        start: bool,
        end: bool,
        skip: usize,
        data: &[u8],
    ) -> (Option<PropUpdate>, bool) {
        debug!("Analyzing tls packet...");
        if skip != 0 {
            return (None, true);
        }

        if data.is_empty() {
            return (None, false);
        }

        let mut update: Option<PropUpdate> = None;
        let cancelled: bool;

        if rev {
            // It's a response message.
            self.resp_buf.extend_from_slice(data);
            self.resp_updated = false;

            let lsm = self.resp_lsm.clone();
            (cancelled, self.resp_done) = (*lsm).write().unwrap().run(self);

            if self.resp_updated {
                let mut resp = PropMap::new();
                resp.insert(
                    "resp".to_string(),
                    serde_json::Value::Object(self.resp_map.clone()),
                );
                update = Some(PropUpdate {
                    update_type: PropUpdateType::Merge,
                    map: resp,
                });
                self.resp_updated = false;
            }
        } else {
            // It's a request message.
            self.req_buf.extend_from_slice(data);
            self.req_updated = false;

            let lsm = self.req_lsm.clone();
            (cancelled, self.req_done) = (*lsm).write().unwrap().run(self);

            if self.req_updated {
                let mut req = PropMap::new();
                req.insert(
                    "req".to_string(),
                    serde_json::Value::Object(self.req_map.clone()),
                );
                update = Some(PropUpdate {
                    update_type: PropUpdateType::Merge,
                    map: req,
                });
                self.req_updated = false;
            }
        }

        (update, cancelled || (self.req_done && self.resp_done))
    }

    #[allow(unused_variables)]
    fn close(&mut self, limited: bool) -> Option<PropUpdate> {
        self.req_buf.clear();
        self.resp_buf.clear();

        self.req_map.clear();
        self.resp_map.clear();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};

    #[test]
    fn test_tls_stream_parsing_client_hello() {
        let client_hello = vec![
            0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x00, 0x00, 0x20, 0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b,
            0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d,
            0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x58, 0x00, 0x00,
            0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x05,
            0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00,
            0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
            0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06,
            0x01, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12,
            0x00, 0x00,
        ];

        let mut want = Map::new();
        want.insert(
            "ciphers".to_string(),
            Value::Array(vec![
                Value::Number(52392.into()),
                Value::Number(52393.into()),
                Value::Number(49199.into()),
                Value::Number(49200.into()),
                Value::Number(49195.into()),
                Value::Number(49196.into()),
                Value::Number(49171.into()),
                Value::Number(49161.into()),
                Value::Number(49172.into()),
                Value::Number(49162.into()),
                Value::Number(156.into()),
                Value::Number(157.into()),
                Value::Number(47.into()),
                Value::Number(53.into()),
                Value::Number(49170.into()),
                Value::Number(10.into()),
            ]),
        );
        want.insert(
            "compression".to_string(),
            Value::Array(vec![Value::Number(0.into())]),
        );
        want.insert(
            "random".to_string(),
            Value::Array((0..32).map(|n| Value::Number(n.into())).collect()),
        );
        want.insert("session".to_string(), Value::Array(Vec::new()));
        want.insert(
            "sni".to_string(),
            Value::String("example.ulfheim.net".into()),
        );
        want.insert("version".to_string(), Value::Number(771.into()));

        let mut s = super::TLSStream::new();
        let (got, _) = s.feed(false, false, false, 0, &client_hello);
        assert_eq!(got.unwrap().map.get("req").unwrap(), &Value::Object(want));
    }

    #[test]
    fn test_tls_stream_parsing_server_hello() {
        let server_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x31, 0x02, 0x00, 0x00, 0x2d, 0x03, 0x03, 0x70, 0x71, 0x72,
            0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
            0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
            0x8f, 0x00, 0xc0, 0x13, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00,
        ];

        let mut want = Map::new();
        want.insert("cipher".to_string(), Value::Number(49171.into()));
        want.insert("compression".to_string(), Value::Number(0.into()));
        want.insert(
            "random".to_string(),
            Value::Array((112..144).map(|n| Value::Number(n.into())).collect()),
        );
        want.insert("session".to_string(), Value::Array(Vec::new()));
        want.insert("version".to_string(), Value::Number(771.into()));

        let mut s = super::TLSStream::new();
        let (got, _) = s.feed(true, false, false, 0, &server_hello);
        assert_eq!(got.unwrap().map.get("resp").unwrap(), &Value::Object(want));
    }
}
