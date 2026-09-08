// SPDX-License-Identifier: MIT OR Apache-2.0

//! A JSON reader for the shapes `script_assets_test.json` uses: objects and arrays of
//! strings, integers and booleans, no floats and no escapes beyond `\"` `\\` `\/`.
//!
//! The corpus is one array of records and can run to hundreds of megabytes, so the reader
//! parses one value from a position and returns the position after it; the runner walks the
//! top-level array record by record, holding one record's tree at a time. A malformed file
//! is a panic with the byte offset: the file is Core's output, not user input.

/// A JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    /// A string, with the three escapes above resolved.
    Str(String),
    /// An integer.
    Number(i64),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// An array.
    Array(Vec<Json>),
    /// An object, fields in file order.
    Object(Vec<(String, Json)>),
}

/// A container under construction.
enum Frame {
    Array(Vec<Json>),
    Object {
        fields: Vec<(String, Json)>,
        key: Option<String>,
    },
}

impl Json {
    /// Parses the value starting at `position` (whitespace allowed before it) and returns
    /// it with the position of the first byte after it.
    #[must_use]
    pub fn parse_at(bytes: &[u8], position: usize) -> (Json, usize) {
        let mut stack: Vec<Frame> = Vec::new();
        let mut position = skip_whitespace(bytes, position);
        let start = position;
        // Every step consumes at least one byte, so the byte count bounds the loop.
        for _ in start..=bytes.len() {
            let (token, next) = read_token(bytes, position, &mut stack);
            assert!(next > position);
            position = next;
            let Some(value) = token else {
                position = skip_whitespace(bytes, position);
                continue;
            };
            match stack.last_mut() {
                None => return (value, position),
                Some(Frame::Array(items)) => items.push(value),
                Some(Frame::Object { fields, key }) => {
                    let key = key
                        .take()
                        .unwrap_or_else(|| panic!("value without key at {position}"));
                    fields.push((key, value));
                }
            }
            position = skip_whitespace(bytes, position);
        }
        panic!("the JSON value at {start} did not terminate");
    }

    /// Parses one whole document.
    #[must_use]
    pub fn parse(text: &str) -> Json {
        let bytes = text.as_bytes();
        let (value, end) = Json::parse_at(bytes, 0);
        assert_eq!(
            skip_whitespace(bytes, end),
            bytes.len(),
            "bytes after the JSON value"
        );
        value
    }

    /// The field `key` of an object, if present.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&Json> {
        let Json::Object(fields) = self else {
            panic!("not an object")
        };
        fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// The field `key` of an object; panics if absent.
    #[must_use]
    pub fn get(&self, key: &str) -> &Json {
        self.field(key)
            .unwrap_or_else(|| panic!("missing key {key}"))
    }

    /// The items of an array.
    #[must_use]
    pub fn as_array(&self) -> &[Json] {
        let Json::Array(items) = self else {
            panic!("not an array")
        };
        items
    }

    /// The text of a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let Json::Str(text) = self else {
            panic!("not a string")
        };
        text
    }

    /// The value of a number.
    #[must_use]
    pub fn as_i64(&self) -> i64 {
        let Json::Number(number) = self else {
            panic!("not a number")
        };
        *number
    }

    /// The value of a boolean.
    #[must_use]
    pub fn as_bool(&self) -> bool {
        let Json::Bool(value) = self else {
            panic!("not a boolean")
        };
        *value
    }
}

/// Reads one token at `position`. A container opener pushes a frame and yields nothing; a
/// closer pops its frame and yields the container; a string inside an object that has no
/// pending key becomes that key and yields nothing; `,` and `:` yield nothing; everything
/// else yields a value.
fn read_token(bytes: &[u8], position: usize, stack: &mut Vec<Frame>) -> (Option<Json>, usize) {
    let byte = *bytes
        .get(position)
        .unwrap_or_else(|| panic!("unterminated JSON at {position}"));
    match byte {
        b'[' => {
            stack.push(Frame::Array(Vec::new()));
            (None, position + 1)
        }
        b'{' => {
            stack.push(Frame::Object {
                fields: Vec::new(),
                key: None,
            });
            (None, position + 1)
        }
        b']' => match stack.pop() {
            Some(Frame::Array(items)) => (Some(Json::Array(items)), position + 1),
            _ => panic!("unmatched ] at {position}"),
        },
        b'}' => match stack.pop() {
            Some(Frame::Object { fields, key: None }) => (Some(Json::Object(fields)), position + 1),
            _ => panic!("unmatched or dangling-key }} at {position}"),
        },
        b',' | b':' => (None, position + 1),
        b'"' => {
            let (text, next) = read_string(bytes, position);
            if let Some(Frame::Object {
                key: key @ None, ..
            }) = stack.last_mut()
            {
                *key = Some(text);
                return (None, next);
            }
            (Some(Json::Str(text)), next)
        }
        b't' => read_literal(bytes, position, b"true", Json::Bool(true)),
        b'f' => read_literal(bytes, position, b"false", Json::Bool(false)),
        b'n' => read_literal(bytes, position, b"null", Json::Null),
        b'-' | b'0'..=b'9' => read_number(bytes, position),
        other => panic!("unexpected byte {other:#04x} at {position}"),
    }
}

fn skip_whitespace(bytes: &[u8], mut position: usize) -> usize {
    while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
        position += 1;
    }
    assert!(position <= bytes.len());
    position
}

/// A string starting at the opening quote; returns it and the position after the closing
/// quote.
fn read_string(bytes: &[u8], position: usize) -> (String, usize) {
    assert_eq!(bytes.get(position), Some(&b'"'));
    let mut text = Vec::new();
    let mut cursor = position + 1;
    // Each step consumes one or two bytes, so the remaining length bounds the loop.
    let remaining = bytes.len() - position;
    for _ in 0..=remaining {
        let byte = *bytes
            .get(cursor)
            .unwrap_or_else(|| panic!("unterminated string at {position}"));
        cursor += 1;
        match byte {
            b'"' => {
                let text = String::from_utf8(text).expect("the corpus is UTF-8");
                return (text, cursor);
            }
            b'\\' => {
                let escaped = *bytes
                    .get(cursor)
                    .unwrap_or_else(|| panic!("dangling \\ at {cursor}"));
                assert!(
                    matches!(escaped, b'"' | b'\\' | b'/'),
                    "unsupported escape at {cursor}"
                );
                text.push(escaped);
                cursor += 1;
            }
            _ => text.push(byte),
        }
    }
    panic!("unterminated string at {position}");
}

fn read_literal(
    bytes: &[u8],
    position: usize,
    literal: &[u8],
    value: Json,
) -> (Option<Json>, usize) {
    let end = position + literal.len();
    assert_eq!(
        bytes.get(position..end),
        Some(literal),
        "bad literal at {position}"
    );
    (Some(value), end)
}

fn read_number(bytes: &[u8], position: usize) -> (Option<Json>, usize) {
    let mut end = position + 1;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    assert!(
        !bytes
            .get(end)
            .is_some_and(|b| matches!(b, b'.' | b'e' | b'E')),
        "no floats at {position}"
    );
    let text = core::str::from_utf8(bytes.get(position..end).expect("in range")).expect("ASCII");
    let number: i64 = text
        .parse()
        .unwrap_or_else(|_| panic!("bad number {text} at {position}"));
    (Some(Json::Number(number)), end)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        reason = "test-only code: an index out of bounds fails the test with a panic, as intended"
    )]

    use super::Json;

    #[test]
    fn reads_the_record_shape() {
        let text = r#" [ {"tx": "0100", "prevouts": ["aa", "bb"], "index": 1,
            "flags": "P2SH,WITNESS",
            "comment": "a \"quoted\" \\ name", "final": true,
            "success": {"scriptSig": "", "witness": []}}, {"n": -7, "z": null} ] "#;
        let doc = Json::parse(text);
        let records = doc.as_array();
        assert_eq!(records.len(), 2);
        let first = &records[0];
        assert_eq!(first.get("tx").as_str(), "0100");
        assert_eq!(first.get("prevouts").as_array().len(), 2);
        assert_eq!(first.get("index").as_i64(), 1);
        assert_eq!(first.get("comment").as_str(), "a \"quoted\" \\ name");
        assert!(first.get("final").as_bool());
        assert!(first.field("failure").is_none());
        assert!(first.get("success").get("witness").as_array().is_empty());
        assert_eq!(records[1].get("n").as_i64(), -7);
        assert_eq!(records[1].get("z"), &Json::Null);
    }

    #[test]
    fn parse_at_walks_an_array_one_item_at_a_time() {
        let bytes = b"[ {\"a\": 1} ,\n {\"a\": 2} ]";
        let mut position = 1;
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (item, next) = Json::parse_at(bytes, position);
            seen.push(item.get("a").as_i64());
            position = next;
            while matches!(bytes.get(position), Some(b',' | b' ' | b'\n')) {
                position += 1;
            }
        }
        assert_eq!(seen, vec![1, 2]);
        assert_eq!(bytes.get(position), Some(&b']'));
    }

    #[test]
    #[should_panic(expected = "no floats")]
    fn floats_are_refused() {
        assert_eq!(Json::parse("1.5"), Json::Null);
    }
}
