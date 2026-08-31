use legacy_ios_core::Ecid;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryDeviceInfo {
    serial_string: String,
    cpid: Option<u32>,
    cprv: Option<u32>,
    cpfm: Option<u32>,
    scep: Option<u32>,
    bdid: Option<u32>,
    ecid: Option<Ecid>,
    ibfl: Option<u32>,
    serial_number: Option<String>,
    imei: Option<String>,
    srtg: Option<String>,
    pwned: Option<String>,
    ap_nonce: Option<Vec<u8>>,
    sep_nonce: Option<Vec<u8>>,
}

impl RecoveryDeviceInfo {
    pub fn serial_string(&self) -> &str {
        &self.serial_string
    }

    pub const fn cpid(&self) -> Option<u32> {
        self.cpid
    }

    pub fn effective_cpid(&self) -> u32 {
        self.cpid.unwrap_or(0x8900)
    }

    pub const fn cprv(&self) -> Option<u32> {
        self.cprv
    }

    pub const fn cpfm(&self) -> Option<u32> {
        self.cpfm
    }

    pub const fn scep(&self) -> Option<u32> {
        self.scep
    }

    pub const fn bdid(&self) -> Option<u32> {
        self.bdid
    }

    pub const fn ecid(&self) -> Option<Ecid> {
        self.ecid
    }

    pub const fn ibfl(&self) -> Option<u32> {
        self.ibfl
    }

    pub fn serial_number(&self) -> Option<&str> {
        self.serial_number.as_deref()
    }

    pub fn imei(&self) -> Option<&str> {
        self.imei.as_deref()
    }

    pub fn srtg(&self) -> Option<&str> {
        self.srtg.as_deref()
    }

    pub fn pwned(&self) -> Option<&str> {
        self.pwned.as_deref()
    }

    pub fn ap_nonce(&self) -> Option<&[u8]> {
        self.ap_nonce.as_deref()
    }

    pub fn sep_nonce(&self) -> Option<&[u8]> {
        self.sep_nonce.as_deref()
    }
}

pub fn parse_iboot_serial(serial: &str) -> RecoveryDeviceInfo {
    RecoveryDeviceInfo {
        serial_string: serial.to_owned(),
        cpid: hex_number(serial, "CPID"),
        cprv: hex_number(serial, "CPRV"),
        cpfm: hex_number(serial, "CPFM"),
        scep: hex_number(serial, "SCEP"),
        bdid: hex_number(serial, "BDID"),
        ecid: hex_number(serial, "ECID").map(Ecid::new),
        ibfl: hex_number(serial, "IBFL"),
        serial_number: bracket_value(serial, "SRNM"),
        imei: bracket_value(serial, "IMEI"),
        srtg: bracket_value(serial, "SRTG"),
        pwned: bracket_value(serial, "PWND"),
        ap_nonce: hex_bytes(serial, "NONC"),
        sep_nonce: hex_bytes(serial, "SNON"),
    }
}

fn field_value<'a>(source: &'a str, tag: &str) -> Option<&'a str> {
    let value = source
        .split_whitespace()
        .find_map(|field| field.strip_prefix(tag))?;
    value.strip_prefix(':')
}

fn hex_number<T>(source: &str, tag: &str) -> Option<T>
where
    T: TryFrom<u64>,
{
    let value = field_value(source, tag)?;
    let parsed = u64::from_str_radix(value, 16).ok()?;
    T::try_from(parsed).ok()
}

fn bracket_value(source: &str, tag: &str) -> Option<String> {
    let prefix = format!("{tag}:[");
    let start = source.find(&prefix)? + prefix.len();
    let end = source[start..].find(']')? + start;
    Some(source[start..end].to_owned())
}

fn hex_bytes(source: &str, tag: &str) -> Option<Vec<u8>> {
    let value = field_value(source, tag)?;
    if !value.len().is_multiple_of(2) {
        return None;
    }

    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_recovery_serial_metadata() {
        let serial = concat!(
            "CPID:8010 CPRV:11 CPFM:03 SCEP:01 BDID:02 ",
            "ECID:0011223344556677 IBFL:3C ",
            "SRNM:[C39TEST] IMEI:[123456789012345] ",
            "SRTG:[iBoot-2696.0.0.1.33] PWND:[checkm8] ",
            "NONC:0011AABB SNON:10203040"
        );

        let info = parse_iboot_serial(serial);

        assert_eq!(info.cpid(), Some(0x8010));
        assert_eq!(info.ecid(), Some(Ecid::new(0x0011_2233_4455_6677)));
        assert_eq!(info.serial_number(), Some("C39TEST"));
        assert_eq!(info.pwned(), Some("checkm8"));
        assert_eq!(info.ap_nonce(), Some([0x00, 0x11, 0xaa, 0xbb].as_slice()));
    }

    #[test]
    fn uses_early_device_cpid_when_serial_has_no_tag() {
        let info = parse_iboot_serial("SRTG:[iBoot-1.0]");

        assert_eq!(info.cpid(), None);
        assert_eq!(info.effective_cpid(), 0x8900);
    }
}
