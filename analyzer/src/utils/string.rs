/// Convert Vec<u8> (which stores the actual data) of the DNS record (whose type is TXT) into Vec<String> separated by whitespace
///
/// Not used for now.
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
pub fn byte_vec_to_strings(bytes: Vec<u8>) -> Vec<String> {
    bytes
        .split(|&b| b == b' ')
        .map(|slice| String::from_utf8(slice.to_vec()).unwrap())
        .collect()
}
