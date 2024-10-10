use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum MaybeUtfChunk<'a> {
    Str(&'a str),
    Bytes(&'a [u8]),
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum UtfChunked<'a> {
    Single(MaybeUtfChunk<'a>),
    Sequence(Vec<MaybeUtfChunk<'a>>),
}

impl<'a> From<&'a [u8]> for UtfChunked<'a> {
    fn from(buf: &'a [u8]) -> UtfChunked<'a> {
        let mut chunks = Vec::new();
        let mut invalid_chunk_start = 0;
        let mut invalid_chunk_len = 0;
        for chunk in buf.utf8_chunks() {
            let valid = chunk.valid();
            if !valid.is_empty() {
                if invalid_chunk_len > 0 {
                    chunks.push(MaybeUtfChunk::Bytes(
                        &buf[invalid_chunk_start..invalid_chunk_start + invalid_chunk_len],
                    ));
                    invalid_chunk_start += invalid_chunk_len;
                    invalid_chunk_len = 0;
                }

                chunks.push(MaybeUtfChunk::Str(valid));
                invalid_chunk_start += valid.len();
            }
            let invalid = chunk.invalid();
            if !invalid.is_empty() {
                invalid_chunk_len += invalid.len();
            }
        }
        if invalid_chunk_len > 0 {
            chunks.push(MaybeUtfChunk::Bytes(
                &buf[invalid_chunk_start..invalid_chunk_start + invalid_chunk_len],
            ));
        }

        match chunks.len() {
            0 => UtfChunked::Single(MaybeUtfChunk::Str("")),
            1 => UtfChunked::Single(chunks.pop().unwrap()),
            _ => UtfChunked::Sequence(chunks),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum OwnedMaybeUtfChunk {
    Str(String),
    Bytes(Vec<u8>),
}

impl OwnedMaybeUtfChunk {
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            OwnedMaybeUtfChunk::Str(s) => s.into_bytes(),
            OwnedMaybeUtfChunk::Bytes(b) => b,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum OwnedUtfChunked {
    Single(OwnedMaybeUtfChunk),
    Sequence(Vec<OwnedMaybeUtfChunk>),
}

impl OwnedUtfChunked {
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            OwnedUtfChunked::Single(c) => c.into_vec(),
            OwnedUtfChunked::Sequence(s) => s.into_iter().flat_map(|c| c.into_vec()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::utf_chunked::{OwnedUtfChunked, UtfChunked};

    #[test]
    fn test_serde_into_chunks_empty() {
        let c = UtfChunked::from(b"".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#""""#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"");
    }

    #[test]
    fn test_serde_into_chunks_valid() {
        let c = UtfChunked::from(b"foo".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#""foo""#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"foo");
    }

    #[test]
    fn test_serde_into_chunks_invalid() {
        let c = UtfChunked::from(b"\xff".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"[255]"#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"\xff");
    }

    #[test]
    fn test_serde_into_chunks_invalid2() {
        let c = UtfChunked::from(b"\xff\xfe".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"[255,254]"#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"\xff\xfe");
    }

    #[test]
    fn test_serde_into_chunks_invalid3() {
        let s = "żółć";
        let mut v = s.as_bytes().to_vec();
        v.push(255);
        v.push(254);
        v.extend(s.as_bytes().iter().cloned());
        let c = UtfChunked::from(v.as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"["żółć",[255,254],"żółć"]"#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), v);
    }

    #[test]
    fn test_serde_into_chunks_vi() {
        let c = UtfChunked::from(b"foo\xff".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"["foo",[255]]"#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"foo\xff");
    }

    #[test]
    fn test_serde_into_chunks_iv() {
        let c = UtfChunked::from(b"\xfffoo".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"[[255],"foo"]"#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"\xfffoo");
    }

    #[test]
    fn test_serde_into_chunks_viv() {
        let c = UtfChunked::from(b"foo\xffbar".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"["foo",[255],"bar"]"#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"foo\xffbar");
    }

    #[test]
    fn test_serde_into_chunks_ivi() {
        let c = UtfChunked::from(b"\xfefoo\xff".as_slice());
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"[[254],"foo",[255]]"#);

        let c2: OwnedUtfChunked = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.into_vec(), b"\xfefoo\xff");
    }
}
