use std::collections::BTreeMap;

use crate::{ContractError, ContractErrorKind};

const MAX_JSON_DEPTH: usize = 64;

#[derive(Debug, PartialEq)]
pub(crate) enum StrictJsonValue {
    Null,
    Bool,
    Number(String),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    contract_path: &'static str,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8], contract_path: &'static str) -> Self {
        Self {
            input,
            position: 0,
            contract_path,
        }
    }

    fn parse(mut self) -> Result<StrictJsonValue, ContractError> {
        self.skip_whitespace();
        let value = self.value(0)?;
        self.skip_whitespace();
        if self.position != self.input.len() {
            return self.invalid_json("input must contain exactly one JSON value");
        }
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<StrictJsonValue, ContractError> {
        if depth > MAX_JSON_DEPTH {
            return self.invalid_json("JSON nesting exceeds the contract limit");
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(StrictJsonValue::String),
            Some(b't') => {
                self.literal(b"true")?;
                Ok(StrictJsonValue::Bool)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(StrictJsonValue::Bool)
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(StrictJsonValue::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.number().map(StrictJsonValue::Number),
            _ => self.invalid_json("invalid JSON value"),
        }
    }

    fn object(&mut self, depth: usize) -> Result<StrictJsonValue, ContractError> {
        self.consume(b'{')?;
        self.skip_whitespace();
        let mut values = BTreeMap::new();
        if self.take_if(b'}') {
            return Ok(StrictJsonValue::Object(values));
        }

        loop {
            if self.peek() != Some(b'"') {
                return self.invalid_json("JSON object keys must be strings");
            }
            let key = self.string()?;
            if values.contains_key(&key) {
                return Err(ContractError::new(
                    ContractErrorKind::DuplicateKey,
                    self.contract_path,
                    "duplicate JSON object keys are forbidden",
                ));
            }
            self.skip_whitespace();
            self.consume(b':')?;
            self.skip_whitespace();
            let value = self.value(depth + 1)?;
            values.insert(key, value);
            self.skip_whitespace();
            if self.take_if(b'}') {
                break;
            }
            self.consume(b',')?;
            self.skip_whitespace();
        }
        Ok(StrictJsonValue::Object(values))
    }

    fn array(&mut self, depth: usize) -> Result<StrictJsonValue, ContractError> {
        self.consume(b'[')?;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.take_if(b']') {
            return Ok(StrictJsonValue::Array(values));
        }

        loop {
            values.push(self.value(depth + 1)?);
            self.skip_whitespace();
            if self.take_if(b']') {
                break;
            }
            self.consume(b',')?;
            self.skip_whitespace();
        }
        Ok(StrictJsonValue::Array(values))
    }

    fn string(&mut self) -> Result<String, ContractError> {
        self.consume(b'"')?;
        let mut decoded = Vec::new();
        loop {
            let Some(byte) = self.next() else {
                return self.invalid_json("unterminated JSON string");
            };
            match byte {
                b'"' => break,
                b'\\' => {
                    let Some(escaped) = self.next() else {
                        return self.invalid_json("unterminated JSON escape");
                    };
                    match escaped {
                        b'"' | b'\\' | b'/' => decoded.push(escaped),
                        b'b' => decoded.push(0x08),
                        b'f' => decoded.push(0x0c),
                        b'n' => decoded.push(b'\n'),
                        b'r' => decoded.push(b'\r'),
                        b't' => decoded.push(b'\t'),
                        b'u' => decoded.push(self.unicode_escape()?),
                        _ => return self.invalid_json("invalid JSON string escape"),
                    }
                }
                0x00..=0x1f => return self.invalid_json("unescaped control byte in JSON string"),
                _ => decoded.push(byte),
            }
        }
        String::from_utf8(decoded)
            .map_err(|_| self.error(ContractErrorKind::NonAscii, "decoded strings must be ASCII"))
    }

    fn unicode_escape(&mut self) -> Result<u8, ContractError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let Some(byte) = self.next() else {
                return self.invalid_json("incomplete JSON unicode escape");
            };
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a') + 10,
                b'A'..=b'F' => u16::from(byte - b'A') + 10,
                _ => return self.invalid_json("invalid JSON unicode escape"),
            };
            value = value * 16 + digit;
        }
        if value == 0 {
            return Err(self.error(ContractErrorKind::NulByte, "decoded NUL is forbidden"));
        }
        if value > 0x7f {
            return Err(self.error(
                ContractErrorKind::NonAscii,
                "decoded strings must contain ASCII only",
            ));
        }
        Ok(value as u8)
    }

    fn number(&mut self) -> Result<String, ContractError> {
        let start = self.position;
        self.take_if(b'-');
        match self.peek() {
            Some(b'0') => {
                self.position += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return self.invalid_json("JSON numbers must not contain leading zeros");
                }
            }
            Some(b'1'..=b'9') => {
                self.position += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return self.invalid_json("invalid JSON number"),
        }

        if self.take_if(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.invalid_json("JSON fraction requires a digit");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.invalid_json("JSON exponent requires a digit");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }

        Ok(std::str::from_utf8(&self.input[start..self.position])
            .expect("input was prevalidated as UTF-8")
            .to_owned())
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), ContractError> {
        if self
            .input
            .get(self.position..self.position + expected.len())
            != Some(expected)
        {
            return self.invalid_json("invalid JSON literal");
        }
        self.position += expected.len();
        Ok(())
    }

    fn consume(&mut self, expected: u8) -> Result<(), ContractError> {
        if self.take_if(expected) {
            Ok(())
        } else {
            self.invalid_json("invalid JSON punctuation")
        }
    }

    fn take_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.position += 1;
        Some(value)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn invalid_json<T>(&self, message: &'static str) -> Result<T, ContractError> {
        Err(self.error(ContractErrorKind::InvalidJson, message))
    }

    fn error(&self, kind: ContractErrorKind, message: &'static str) -> ContractError {
        ContractError::new(kind, self.contract_path, message)
    }
}

pub(crate) fn parse_strict_json(
    input: &[u8],
    maximum_bytes: usize,
    contract_path: &'static str,
) -> Result<StrictJsonValue, ContractError> {
    if input.len() > maximum_bytes {
        return Err(ContractError::new(
            ContractErrorKind::InputTooLarge,
            contract_path,
            "input exceeds the contract byte limit",
        ));
    }
    if input.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(ContractError::new(
            ContractErrorKind::ByteOrderMark,
            contract_path,
            "UTF-8 byte-order marks are forbidden",
        ));
    }
    if input.contains(&0) {
        return Err(ContractError::new(
            ContractErrorKind::NulByte,
            contract_path,
            "NUL bytes are forbidden",
        ));
    }
    let text = std::str::from_utf8(input).map_err(|_| {
        ContractError::new(
            ContractErrorKind::InvalidUtf8,
            contract_path,
            "input must be valid UTF-8",
        )
    })?;
    if !text.is_ascii() {
        return Err(ContractError::new(
            ContractErrorKind::NonAscii,
            contract_path,
            "input must contain ASCII bytes only",
        ));
    }

    Parser::new(input, contract_path).parse()
}

pub(crate) fn exact_object(
    value: StrictJsonValue,
    allowed: &[(&'static str, &'static str)],
    path: &'static str,
) -> Result<BTreeMap<String, StrictJsonValue>, ContractError> {
    let StrictJsonValue::Object(values) = value else {
        return Err(ContractError::new(
            ContractErrorKind::InvalidJson,
            path,
            "value must be a JSON object",
        ));
    };

    for key in values.keys() {
        if !allowed.iter().any(|(allowed_key, _)| key == allowed_key) {
            return Err(ContractError::new(
                ContractErrorKind::UnknownField,
                path,
                "object contains a field outside the closed contract",
            ));
        }
    }
    for (key, field_path) in allowed {
        if !values.contains_key(*key) {
            return Err(ContractError::new(
                ContractErrorKind::MissingField,
                field_path,
                "required field is missing",
            ));
        }
    }
    Ok(values)
}

pub(crate) fn take(values: &mut BTreeMap<String, StrictJsonValue>, key: &str) -> StrictJsonValue {
    values
        .remove(key)
        .expect("exact_object guarantees every required field")
}

pub(crate) fn exact_string(
    value: StrictJsonValue,
    expected: &str,
    path: &'static str,
) -> Result<(), ContractError> {
    match value {
        StrictJsonValue::String(actual) if actual == expected => Ok(()),
        _ => Err(ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            "field does not equal its required literal",
        )),
    }
}

pub(crate) fn string(value: StrictJsonValue, path: &'static str) -> Result<String, ContractError> {
    match value {
        StrictJsonValue::String(actual) => Ok(actual),
        _ => Err(ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            "field must be a JSON string",
        )),
    }
}

pub(crate) fn exact_one(value: StrictJsonValue, path: &'static str) -> Result<(), ContractError> {
    match value {
        StrictJsonValue::Number(number) if number == "1" => Ok(()),
        _ => Err(ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            "field must be the canonical JSON integer 1",
        )),
    }
}

pub(crate) fn empty_array(value: StrictJsonValue, path: &'static str) -> Result<(), ContractError> {
    match value {
        StrictJsonValue::Array(values) if values.is_empty() => Ok(()),
        _ => Err(ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            "field must be an empty JSON array",
        )),
    }
}

pub(crate) fn singleton_string_array(
    value: StrictJsonValue,
    expected: &str,
    path: &'static str,
) -> Result<(), ContractError> {
    match value {
        StrictJsonValue::Array(mut values) if values.len() == 1 => {
            exact_string(values.remove(0), expected, path)
        }
        _ => Err(ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            "field must contain exactly one required string",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict_json;

    #[test]
    fn every_shipped_json_document_is_strict_valid_json() {
        for document in [
            include_bytes!("../package.json").as_slice(),
            include_bytes!("../schemas/provisioning-request.v1.schema.json").as_slice(),
            include_bytes!("../schemas/systemd-hardening.v1.schema.json").as_slice(),
            include_bytes!("../data/systemd-hardening.v1.json").as_slice(),
        ] {
            parse_strict_json(document, 4_096, "$shipped_json").unwrap();
        }
    }
}
