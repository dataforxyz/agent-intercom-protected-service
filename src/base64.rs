#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Base64Error {
    InvalidEncoding,
    DecodedTooLarge,
}

pub(crate) fn decode_canonical_padded(
    input: &str,
    maximum_decoded_bytes: usize,
) -> Result<Vec<u8>, Base64Error> {
    let input = input.as_bytes();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() % 4 != 0 {
        return Err(Base64Error::InvalidEncoding);
    }

    let mut decoded = Vec::with_capacity((input.len() / 4 * 3).min(maximum_decoded_bytes));
    for (index, quartet) in input.chunks_exact(4).enumerate() {
        let final_quartet = index + 1 == input.len() / 4;
        let first = sextet(quartet[0]).ok_or(Base64Error::InvalidEncoding)?;
        let second = sextet(quartet[1]).ok_or(Base64Error::InvalidEncoding)?;

        match (quartet[2], quartet[3]) {
            (b'=', b'=') if final_quartet && second & 0x0f == 0 => {
                push_bounded(
                    &mut decoded,
                    (first << 2) | (second >> 4),
                    maximum_decoded_bytes,
                )?;
            }
            (third, b'=') if final_quartet => {
                let third = sextet(third).ok_or(Base64Error::InvalidEncoding)?;
                if third & 0x03 != 0 {
                    return Err(Base64Error::InvalidEncoding);
                }
                push_bounded(
                    &mut decoded,
                    (first << 2) | (second >> 4),
                    maximum_decoded_bytes,
                )?;
                push_bounded(
                    &mut decoded,
                    (second << 4) | (third >> 2),
                    maximum_decoded_bytes,
                )?;
            }
            (third, fourth) => {
                let third = sextet(third).ok_or(Base64Error::InvalidEncoding)?;
                let fourth = sextet(fourth).ok_or(Base64Error::InvalidEncoding)?;
                push_bounded(
                    &mut decoded,
                    (first << 2) | (second >> 4),
                    maximum_decoded_bytes,
                )?;
                push_bounded(
                    &mut decoded,
                    (second << 4) | (third >> 2),
                    maximum_decoded_bytes,
                )?;
                push_bounded(&mut decoded, (third << 6) | fourth, maximum_decoded_bytes)?;
            }
        }
    }

    if encode_padded(&decoded).as_bytes() != input {
        return Err(Base64Error::InvalidEncoding);
    }
    Ok(decoded)
}

pub(crate) fn encode_padded(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        if chunk.len() == 1 {
            encoded.push(char::from(ALPHABET[usize::from((first & 0x03) << 4)]));
            encoded.push('=');
            encoded.push('=');
            continue;
        }

        let second = chunk[1];
        encoded.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() == 2 {
            encoded.push(char::from(ALPHABET[usize::from((second & 0x0f) << 2)]));
            encoded.push('=');
            continue;
        }

        let third = chunk[2];
        encoded.push(char::from(
            ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
        ));
        encoded.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
    }
    encoded
}

fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn push_bounded(
    decoded: &mut Vec<u8>,
    byte: u8,
    maximum_decoded_bytes: usize,
) -> Result<(), Base64Error> {
    if decoded.len() == maximum_decoded_bytes {
        return Err(Base64Error::DecodedTooLarge);
    }
    decoded.push(byte);
    Ok(())
}
