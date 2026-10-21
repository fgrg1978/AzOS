// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The validity window of an X.509 certificate.
//!
//! rustls-webpki checks a chain's dates but a pinned client builds no chain,
//! and no X.509 parser is vendored, so this walks the DER of
//! `Certificate -> TBSCertificate` as far as `validity`: definite lengths up to
//! four bytes, nothing else is read. (The key is not read here: the pin hashes
//! webpki's own SubjectPublicKeyInfo, [`crate::pin`].) Every read is
//! bounds-checked; malformed input is `None`.

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const CONTEXT_0: u8 = 0xA0;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

/// One tag-length-value: the tag, its content, what follows.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
}

fn tlv(buf: &[u8]) -> Option<Tlv<'_>> {
    let tag = *buf.first()?;
    // High-tag-number form is not used by anything this reads.
    if tag & 0x1F == 0x1F {
        return None;
    }
    let first = *buf.get(1)?;
    let (len, head) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        // 0x80 is the indefinite form (BER), which DER does not have.
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = buf.get(2..2 + n)?;
        (bytes.iter().fold(0usize, |a, b| a << 8 | *b as usize), 2 + n)
    };
    let end = head.checked_add(len)?;
    Some(Tlv { tag, content: buf.get(head..end)?, rest: &buf[end..] })
}

fn expect(buf: &[u8], tag: u8) -> Option<Tlv<'_>> {
    tlv(buf).filter(|t| t.tag == tag)
}

/// Days from 1970-01-01 to the civil date (proleptic Gregorian).
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn digits(s: &[u8]) -> Option<u64> {
    s.iter().try_fold(0u64, |a, c| c.is_ascii_digit().then(|| a * 10 + (c - b'0') as u64))
}

/// A UTCTime (`YYMMDDHHMMSSZ`, 1950..2049) or GeneralizedTime
/// (`YYYYMMDDHHMMSSZ`) as seconds since the Unix epoch.
fn time(t: &Tlv<'_>) -> Option<u64> {
    let (year, rest) = match t.tag {
        UTC_TIME if t.content.len() == 13 => {
            let yy = digits(&t.content[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &t.content[2..])
        }
        GENERALIZED_TIME if t.content.len() == 15 => (digits(&t.content[..4])?, &t.content[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let (mon, day, h, mi, s) =
        (digits(&rest[..2])?, digits(&rest[2..4])?, digits(&rest[4..6])?, digits(&rest[6..8])?, digits(&rest[8..10])?);
    if year < 1970 || !(1..=12).contains(&mon) || !(1..=31).contains(&day) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    Some(days_from_civil(year, mon, day) * 86_400 + h * 3600 + mi * 60 + s)
}

/// `(notBefore, notAfter)` of the certificate in `der`, seconds since the Unix epoch.
pub fn validity(der: &[u8]) -> Option<(u64, u64)> {
    let cert = expect(der, SEQUENCE)?;
    let tbs = expect(cert.content, SEQUENCE)?.content;
    // version [0] EXPLICIT, absent in v1
    let mut at = match tlv(tbs)? {
        t if t.tag == CONTEXT_0 => t.rest,
        _ => tbs,
    };
    at = expect(at, INTEGER)?.rest; // serialNumber
    at = expect(at, SEQUENCE)?.rest; // signature
    at = expect(at, SEQUENCE)?.rest; // issuer
    let validity = expect(at, SEQUENCE)?;
    let not_before = tlv(validity.content)?;
    let not_after = tlv(not_before.rest)?;
    Some((time(&not_before)?, time(&not_after)?))
}
