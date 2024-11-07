//! analyzer for tcp/http
use crate::*;
use bytes::BytesMut;
use std::cell::RefCell;
use std::rc::Rc;
// use tracing::error;

/// HTTPAnalyzer is an analyzer for HTTP protocol.
pub struct HTTPAnalyzer {}

impl Analyzer for HTTPAnalyzer {
    fn name(&self) -> &str {
        "http"
    }

    fn limit(&self) -> u32 {
        8192
    }
}

impl TCPAnalyzer for HTTPAnalyzer {
    #[allow(unused_variables)]
    fn new_tcp(&self, info: TCPInfo) -> Box<dyn TCPStream> {
        Box::new(HTTPStream::new())
    }
}

struct HTTPStream {
    req_buf: BytesMut,
    req_map: PropMap,
    req_updated: bool,
    req_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<HTTPStream>>>,
    req_done: bool,

    resp_buf: BytesMut,
    resp_map: PropMap,
    resp_updated: bool,
    resp_lsm: Rc<RefCell<utils::lsm::LinearStateMachine<HTTPStream>>>,
    resp_done: bool,
}

impl HTTPStream {
    fn new() -> Self {
        Self {
            req_buf: BytesMut::new(),
            req_map: PropMap::new(),
            req_updated: false,
            req_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.parse_request_line()),
                Box::new(|s| s.parse_request_headers()),
            ]))),
            req_done: false,

            resp_buf: BytesMut::new(),
            resp_map: PropMap::new(),
            resp_updated: false,
            resp_lsm: Rc::new(RefCell::new(utils::lsm::LinearStateMachine::new(vec![
                Box::new(|s| s.parse_response_line()),
                Box::new(|s| s.parse_response_headers()),
            ]))),
            resp_done: false,
        }
    }

    fn parse_request_line(&mut self) -> utils::lsm::LSMAction {
        if let Some(line) = self.req_buf.split_mut(|&b| b == b'\n').next() {
            let line = String::from_utf8_lossy(&line[..line.len() - 1]); // Strip \r\n
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 3 {
                return utils::lsm::LSMAction::Cancel;
            }
            let method = fields[0].to_string();
            let path = fields[1].to_string();
            let version = fields[2].to_string();
            if !version.starts_with("HTTP/") {
                return utils::lsm::LSMAction::Cancel;
            }
            self.req_map.insert("method".to_string(), Rc::new(method));
            self.req_map.insert("path".to_string(), Rc::new(path));
            self.req_map.insert("version".to_string(), Rc::new(version));
            self.req_updated = true;
            utils::lsm::LSMAction::Next
        } else {
            utils::lsm::LSMAction::Pause
        }
    }

    fn parse_response_line(&mut self) -> utils::lsm::LSMAction {
        if let Some(line) = self.resp_buf.split_mut(|&b| b == b'\n').next() {
            let line = String::from_utf8_lossy(&line[..line.len() - 1]); // Strip \r\n
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 {
                return utils::lsm::LSMAction::Cancel;
            }
            let version = fields[0].to_string();
            let status = fields[1].parse::<u16>().unwrap_or(0);
            if !version.starts_with("HTTP/") || status == 0 {
                return utils::lsm::LSMAction::Cancel;
            }
            self.resp_map
                .insert("version".to_string(), Rc::new(version));
            self.resp_map.insert("status".to_string(), Rc::new(status));
            self.resp_updated = true;
            utils::lsm::LSMAction::Next
        } else {
            utils::lsm::LSMAction::Pause
        }
    }

    fn parse_headers(buf: &mut BytesMut) -> (utils::lsm::LSMAction, PropMap) {
        if let Some(headers) = buf.split_mut(|&b| b == b'\n').next() {
            let headers = &headers[..headers.len() - 1]; // Strip \r\n\r\n
            let mut header_map = PropMap::new();
            for line in headers.split(|&b| b == b'\n') {
                let parts: Vec<&[u8]> = line.splitn(2, |&b| b == b':').collect();
                if parts.len() != 2 {
                    return (utils::lsm::LSMAction::Cancel, PropMap::new());
                }
                let key = String::from_utf8_lossy(parts[0]).trim().to_lowercase();
                let value = String::from_utf8_lossy(parts[1]).trim().to_string();
                header_map.insert(key, Rc::new(value));
            }
            (utils::lsm::LSMAction::Next, header_map)
        } else {
            (utils::lsm::LSMAction::Pause, PropMap::new())
        }
    }

    fn parse_request_headers(&mut self) -> utils::lsm::LSMAction {
        let (action, header_map) = Self::parse_headers(&mut self.req_buf);
        if action == utils::lsm::LSMAction::Next {
            self.req_map
                .insert("headers".to_string(), Rc::new(header_map));
            self.req_updated = true;
        }
        action
    }

    fn parse_response_headers(&mut self) -> utils::lsm::LSMAction {
        let (action, header_map) = Self::parse_headers(&mut self.resp_buf);
        if action == utils::lsm::LSMAction::Next {
            self.resp_map
                .insert("headers".to_string(), Rc::new(header_map));
            self.resp_updated = true;
        }
        action
    }
}

impl TCPStream for HTTPStream {
    #[allow(unused_variables)]
    fn feed(
        &mut self,
        rev: bool,
        start: bool,
        end: bool,
        skip: usize,
        data: &[u8],
    ) -> (Option<PropUpdate>, bool) {
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
            (cancelled, self.resp_done) = (*lsm).borrow_mut().run(self);

            if self.resp_updated {
                update = Some(PropUpdate {
                    update_type: PropUpdateType::Merge,
                    map: self.resp_map.clone(),
                });
                self.resp_updated = false;
            }
        } else {
            // It's a request message.
            self.req_buf.extend_from_slice(data);
            self.req_updated = false;

            let lsm = self.req_lsm.clone();
            (cancelled, self.req_done) = (*lsm).borrow_mut().run(self);

            if self.req_updated {
                update = Some(PropUpdate {
                    update_type: PropUpdateType::Merge,
                    map: self.req_map.clone(),
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
