/// Convert Vec<u8> (which stores the actual data) of the DNS record (whose type is TXT) into Vec<String> separated by whitespace
///
/// # Arguments
///
/// * `bytes` - A vector of bytes.
///
///
/// # Returns
///
/// A vector of strings.
///
/// # Examples
///
/// ```
/// let bytes = b"hello world this is a test".to_vec();
/// let strings = byte_vec_to_strings(bytes);
/// assert_eq!(strings, vec!["hello".to_string(), "world".to_string(), "this".to_string(), "is".to_string(), "a".to_string(), "test".to_string()]);
/// ```
pub fn byte_vec_to_strings(bytes: Vec<u8>) -> Vec<String> {
    bytes
        .split(|&b| b == b' ')
        .map(|slice| String::from_utf8(slice.to_vec()).unwrap())
        .collect()
}
