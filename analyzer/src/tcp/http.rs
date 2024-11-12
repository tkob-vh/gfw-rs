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

    fn limit(&self) -> i32 {
        8192
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TCPAnalyzer for HTTPAnalyzer {
    #[allow(unused_variables)]
    fn new_tcp(&self, info: TCPInfo) -> Box<dyn TCPStream> {
        Box::new(HTTPStream::new())
    }
}

/// HTTPStream is a stream for HTTP protocol.
pub struct HTTPStream {
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

    fn split_at_crlf(buf: &mut BytesMut) -> Option<(BytesMut, BytesMut)> {
        if let Some(pos) = buf.windows(2).position(|window| window == b"\r\n") {
            let part1 = buf.split_to(pos);
            let _ = buf.split_to(2);
            let part2 = buf.clone();
            Some((part1, part2))
        } else {
            None
        }
    }

    fn parse_request_line(&mut self) -> utils::lsm::LSMAction {
        if let Some((line, remaining)) = Self::split_at_crlf(&mut self.req_buf) {
            let line = String::from_utf8_lossy(&line[..line.len()]); // Strip \r\n
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
            self.req_buf = remaining; // Update the buffer with the remaining data
            utils::lsm::LSMAction::Next
        } else {
            utils::lsm::LSMAction::Pause
        }
    }

    fn parse_response_line(&mut self) -> utils::lsm::LSMAction {
        if let Some((line, remaining)) = Self::split_at_crlf(&mut self.resp_buf) {
            let line = String::from_utf8_lossy(&line[..line.len()]); // Strip \r\n
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
            self.resp_buf = remaining; // Update the buffer with the remaining data
            utils::lsm::LSMAction::Next
        } else {
            utils::lsm::LSMAction::Pause
        }
    }

    fn parse_headers(buf: &mut BytesMut) -> (utils::lsm::LSMAction, PropMap) {
        if let Some(headers) = buf.split_mut(|&b| b == b'\n').next() {
            if headers.is_empty() {
                return (utils::lsm::LSMAction::Next, PropMap::new());
            }
            let headers = &headers[..headers.len() - 1];
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, rc::Rc};

    use crate::{PropMap, TCPStream};

    #[test]
    fn test_http_parsing_request() {
        let test_cases = vec![
            ("GET / HTTP/1.1\r\n", {
                let mut map = crate::PropMap::new();
                map.insert("method".to_string(), Rc::new("GET".to_string()));
                map.insert("path".to_string(), Rc::new("/".to_string()));
                map.insert("version".to_string(), Rc::new("HTTP/1.1".to_string()));
                map.insert("headers".to_string(), Rc::new(crate::PropMap::new()));
                map
            }),
            ("POST /hello?a=1&b=2 HTTP/1.0\r\n", {
                let mut map = crate::PropMap::new();
                map.insert("method".to_string(), Rc::new("POST".to_string()));
                map.insert("path".to_string(), Rc::new("/hello?a=1&b=2".to_string()));
                map.insert("version".to_string(), Rc::new("HTTP/1.0".to_string()));
                map.insert("headers".to_string(), Rc::new(crate::PropMap::new()));
                map
            }),
            ("DELETE /goodbye HTTP/2.0\r\n", {
                let mut map = crate::PropMap::new();
                map.insert("method".to_string(), Rc::new("DELETE".to_string()));
                map.insert("path".to_string(), Rc::new("/goodbye".to_string()));
                map.insert("version".to_string(), Rc::new("HTTP/2.0".to_string()));
                map.insert("headers".to_string(), Rc::new(crate::PropMap::new()));
                map
            }),
        ];

        for (tc, want) in test_cases {
            let mut stream = super::HTTPStream::new();
            let (a, _) = stream.feed(false, false, false, 0, tc.as_bytes());
            let result_map = a.unwrap().map; // 获取实际返回的 `map`

            // Check method
            let method = result_map.get("method").unwrap();
            let want_method = want.get("method").unwrap();
            let method = method.downcast_ref::<String>().unwrap();
            let want_method = want_method.downcast_ref::<String>().unwrap();
            assert_eq!(method, want_method);

            // Check path
            let path = result_map.get("path").unwrap();
            let want_path = want.get("path").unwrap();
            let path = path.downcast_ref::<String>().unwrap();
            let want_path = want_path.downcast_ref::<String>().unwrap();
            assert_eq!(path, want_path);

            // Check version
            let version = result_map.get("version").unwrap();
            let want_version = want.get("version").unwrap();
            let version = version.downcast_ref::<String>().unwrap();
            let want_version = want_version.downcast_ref::<String>().unwrap();
            assert_eq!(version, want_version);
        }
    }

    #[test]
    fn test_http_1() {
        let input = ("PUT /world HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody", {
            let mut map = crate::PropMap::new();
            map.insert("method".to_string(), Rc::new("PUT".to_string()));
            map.insert("path".to_string(), Rc::new("/world".to_string()));
            map.insert("version".to_string(), Rc::new("HTTP/1.1".to_string()));
            {
                let mut headers = HashMap::new();
                headers.insert("content-length".to_string(), "4".to_string());
                map.insert("headers".to_string(), Rc::new(headers));
            }
            map
        });

        let mut stream = super::HTTPStream::new();
        let (a, _) = stream.feed(false, false, false, 0, input.0.as_bytes());
        let result_map = a.unwrap().map;
        let want = input.1;
        // Check method
        let method = result_map.get("method").unwrap();
        let want_method = want.get("method").unwrap();
        let method = method.downcast_ref::<String>().unwrap();
        let want_method = want_method.downcast_ref::<String>().unwrap();
        assert_eq!(method, want_method);

        // Check path
        let path = result_map.get("path").unwrap();
        let want_path = want.get("path").unwrap();
        let path = path.downcast_ref::<String>().unwrap();
        let want_path = want_path.downcast_ref::<String>().unwrap();
        assert_eq!(path, want_path);

        // Check version
        let version = result_map.get("version").unwrap();
        let want_version = want.get("version").unwrap();
        let version = version.downcast_ref::<String>().unwrap();
        let want_version = want_version.downcast_ref::<String>().unwrap();
        assert_eq!(version, want_version);

        // Check headers
        let expected_headers = want.get("headers").unwrap();
        let headers = result_map.get("headers").unwrap();

        // Extract the headers HashMap from Rc<dyn Any>
        let result_headers = headers.downcast_ref::<PropMap>().unwrap();
        let expected_headers_map = expected_headers
            .downcast_ref::<HashMap<String, String>>()
            .unwrap();

        // check content-length
        assert_eq!(
            result_headers
                .get("content-length")
                .unwrap()
                .downcast_ref::<String>()
                .unwrap(),
            expected_headers_map.get("content-length").unwrap()
        );
    }
}
