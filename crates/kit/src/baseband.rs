//! The latest-baseband swap of `ipsw_bbreplace` (restore.sh:4342-4438): a
//! two-bundle powder build targeting a non-latest version gets the device's
//! latest baseband firmware, and the BuildManifest `BasebandFirmware`
//! digests, partial digests, loader versions, path, and `UniqueBuildID` are
//! rewritten to the values of the latest-version BuildManifest.
//!
//! The per-device values below are the table upstream hardcodes in
//! `ipsw_bbreplace` (restore.sh @ 1ff4be07ea2946ccaeff2db60c4426488b8f6e32);
//! they are the `BasebandFirmware` entries of the latest iOS BuildManifest
//! for each device (8.4.1 for iPhone4,1, 10.3.4 for the Mav5 devices, 10.3.3
//! for iPhone5,3/5,4).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use legacy_ios_core::ProductType;

use crate::KitError;

/// One device's BuildManifest rewrite of `ipsw_bbreplace`.
pub(crate) struct BasebandRewrite {
    /// `UniqueBuildID` of the latest-version build identity (base64).
    unique_build_id: &'static str,
    /// Loader version keys rewritten to the latest values: the
    /// `RestoreSBL1-Version`/`eDBL-Version` key (upstream's `rsb1`) and the
    /// `SBL1-Version`/`RestoreDBL-Version` key (upstream's `sbl1`).
    version_keys: (&'static str, &'static str),
    /// Latest values of the two loader version keys, in `version_keys` order.
    latest_versions: (i64, i64),
    /// `BasebandFirmware` digest keys and their latest values (base64), in
    /// upstream's `ipsw_bbdigest` call order.
    digests: &'static [(&'static str, &'static str)],
}

/// iPhone4,1 (MDM6610, latest 8.4.1).
const IPHONE4_1_DIGESTS: &[(&str, &str)] = &[
    (
        "RestoreDBL-PartialDigest",
        "XAAAAADHAQCqerR8d+PvcfusucizfQ4ECBI0TA==",
    ),
    ("AMSS-HashTableDigest", "Q1TLjk+/PjayCzSJJo68FTtdhyE="),
    ("OSBL-DownloadDigest", "KkJI7ufv5tfNoqHcrU7gqoycmXA="),
    (
        "eDBL-PartialDigest",
        "eAAAAADIAQDxcjzF1q5t+nvLBbvewn/arYVkLw==",
    ),
    ("AMSS-DownloadDigest", "3CHVk7EmtGjL14ApDND81cqFqhM="),
];

/// iPhone5,1/5,2, iPad2,6/2,7, iPad3,5/3,6 (MDM9615, latest 10.3.4).
const MAV5_DIGESTS: &[(&str, &str)] = &[
    ("APPS-DownloadDigest", "2bmJ7Vd+WAmogV+hjq1a86UlBvA="),
    ("APPS-HashTableDigest", "oNmIZf39zd94CPiiKOpKvhGJbyg="),
    ("DSP1-DownloadDigest", "dFi5J+pSSqOfz31fIvmah2GJO+E="),
    ("DSP1-HashTableDigest", "HXUnmGmwIHbVLxkT1rHLm5V6iDM="),
    ("DSP2-DownloadDigest", "oA5eQ8OurrWrFpkUOhD/3sGR3y8="),
    ("DSP2-HashTableDigest", "L7v8ulq1z1Pr7STR47RsNbxmjf0="),
    ("DSP3-DownloadDigest", "MZ1ERfoeFcbe79pFAl/hbWUSYKc="),
    ("DSP3-HashTableDigest", "sKmLhQcjfaOliydm+iwxucr9DGw="),
    ("RPM-DownloadDigest", "oiW/8qZhN0r9OaLdUHCT+MMGknY="),
    (
        "RestoreSBL1-PartialDigest",
        "fAAAAEAQAgAH58t5X9KETIPrycULi8dg7b2rSw==",
    ),
    (
        "SBL1-PartialDigest",
        "ZAAAAIC9AQAfgUcPMN/lMt+U8s6bxipdy6td6w==",
    ),
    ("SBL2-DownloadDigest", "kHLoJsT9APu4Xwu/aRjNK10Hx84="),
];

/// iPhone5,3/5,4 (MDM9615, latest 10.3.3).
const MAV7MAV8_DIGESTS: &[(&str, &str)] = &[
    ("APPS-DownloadDigest", "TSVi7eYY4FiAzXynDVik6TY2S1c="),
    ("APPS-HashTableDigest", "xd/JBOTxYJWmLkTWqLWl8GeINgU="),
    ("DSP1-DownloadDigest", "RigCEz69gUymh2UdyJdwZVx74Ic="),
    ("DSP1-HashTableDigest", "a3XhREtzynTWtyQGqi/RXorXSVE="),
    ("DSP2-DownloadDigest", "3JTgHWvC+XZYWa5U5MPvle+imj4="),
    ("DSP2-HashTableDigest", "Hvppb92/1o/cWQbl8ftoiW5jOLg="),
    ("DSP3-DownloadDigest", "R60ZfsOqZX+Pd/UnEaEhWfNvVlY="),
    ("DSP3-HashTableDigest", "DFQWkktFWNh90G2hOfwO14oEbrI="),
    ("RPM-DownloadDigest", "Rsn+u2mOpYEmdrw98yA8EDT5LiE="),
    (
        "RestoreSBL1-PartialDigest",
        "cAAAAIC9AQBLeCHzsjHo8Q7+IzELZTV/ri/Vow==",
    ),
    (
        "SBL1-PartialDigest",
        "eAAAAEBsAQB9b44LqXjR3izAYl5gB4j3Iqegkg==",
    ),
    ("SBL2-DownloadDigest", "iog3IVe+8VqgQzP2QspgFRUNwn8="),
];

/// The `case $device_type` table of `ipsw_bbreplace`. Devices upstream does
/// not list (e.g. the A5X/A6X cellular iPads) have no known latest-manifest
/// values and return `None`.
pub(crate) fn baseband_rewrite(product_type: &ProductType) -> Option<BasebandRewrite> {
    let (unique_build_id, version_keys, latest_versions, digests) = match product_type.as_str() {
        "iPhone4,1" => (
            "d9Xbp0xyiFOxDvUcKMsoNjIvhwQ=",
            ("eDBL-Version", "RestoreDBL-Version"),
            (-1_577_031_936, -1_575_983_360),
            IPHONE4_1_DIGESTS,
        ),
        "iPhone5,1" => (
            "IcrFKRzWDvccKDfkfMNPOPYHEV0=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_559_114_512, -1_560_163_088),
            MAV5_DIGESTS,
        ),
        "iPhone5,2" => (
            "lnU0rtBUK6gCyXhEtHuwbEz/IKY=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_559_114_512, -1_560_163_088),
            MAV5_DIGESTS,
        ),
        "iPhone5,3" => (
            "dwrol4czV3ijtNHh3w1lWIdsNdA=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_542_379_296, -1_543_427_872),
            MAV7MAV8_DIGESTS,
        ),
        "iPhone5,4" => (
            "Z4ST0TczwAhpfluQFQNBg7Y3BVE=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_542_379_296, -1_543_427_872),
            MAV7MAV8_DIGESTS,
        ),
        "iPad2,6" => (
            "L73HfN42pH7qAzlWmsEuIZZg2oE=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_559_114_512, -1_560_163_088),
            MAV5_DIGESTS,
        ),
        "iPad2,7" => (
            "z/vJsvnUovZ+RGyXKSFB6DOjt1k=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_559_114_512, -1_560_163_088),
            MAV5_DIGESTS,
        ),
        "iPad3,5" => (
            "849RPGQ9kNXGMztIQBhVoU/l5lM=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_559_114_512, -1_560_163_088),
            MAV5_DIGESTS,
        ),
        "iPad3,6" => (
            "cO+N+Eo8ynFf+0rnsIWIQHTo6rg=",
            ("RestoreSBL1-Version", "SBL1-Version"),
            (-1_559_114_512, -1_560_163_088),
            MAV5_DIGESTS,
        ),
        _ => return None,
    };
    Some(BasebandRewrite {
        unique_build_id,
        version_keys,
        latest_versions,
        digests,
    })
}

fn decode(base64: &str) -> Vec<u8> {
    BASE64
        .decode(base64)
        .expect("the baseband rewrite table holds constant valid base64")
}

/// Rewrite the baseband entries of a BuildManifest for the latest-baseband
/// swap, mirroring the `ipsw_bbdigest` calls and the closing `sed` of
/// `ipsw_bbreplace`: every build identity gains the latest `UniqueBuildID`,
/// and every identity with a `BasebandFirmware` manifest entry gets the
/// latest digests, loader versions, and the new baseband path. Upstream's
/// Linux path is a whole-file text substitution, so all identities are
/// rewritten here (the macOS PlistBuddy path touches only identity 0).
pub(crate) fn rewrite_baseband_manifest(
    manifest: &[u8],
    rewrite: &BasebandRewrite,
    baseband_path: &str,
) -> Result<Vec<u8>, KitError> {
    let mut value = plist::Value::from_reader(std::io::Cursor::new(manifest))?;
    let Some(identities) = value
        .as_dictionary_mut()
        .and_then(|root| root.get_mut("BuildIdentities"))
        .and_then(plist::Value::as_array_mut)
    else {
        return Err(KitError::PowderInvalidManifest);
    };
    for identity in identities {
        let Some(identity) = identity.as_dictionary_mut() else {
            continue;
        };
        identity.insert(
            "UniqueBuildID".to_owned(),
            plist::Value::Data(decode(rewrite.unique_build_id)),
        );
        let Some(baseband) = identity
            .get_mut("Manifest")
            .and_then(plist::Value::as_dictionary_mut)
            .and_then(|manifest| manifest.get_mut("BasebandFirmware"))
            .and_then(plist::Value::as_dictionary_mut)
        else {
            continue;
        };
        for (key, value) in [
            (rewrite.version_keys.0, rewrite.latest_versions.0),
            (rewrite.version_keys.1, rewrite.latest_versions.1),
        ] {
            baseband.insert(key.to_owned(), plist::Value::Integer(value.into()));
        }
        for &(key, digest) in rewrite.digests {
            baseband.insert(key.to_owned(), plist::Value::Data(decode(digest)));
        }
        if let Some(info) = baseband
            .get_mut("Info")
            .and_then(plist::Value::as_dictionary_mut)
        {
            info.insert(
                "Path".to_owned(),
                plist::Value::String(baseband_path.to_owned()),
            );
        }
    }
    let mut output = Vec::new();
    value.to_writer_xml(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_entries_decode_as_base64() {
        for device in [
            "iPhone4,1",
            "iPhone5,1",
            "iPhone5,2",
            "iPhone5,3",
            "iPhone5,4",
            "iPad2,6",
            "iPad2,7",
            "iPad3,5",
            "iPad3,6",
        ] {
            let rewrite = baseband_rewrite(&ProductType::from(device))
                .unwrap_or_else(|| panic!("missing rewrite for {device}"));
            assert!(!decode(rewrite.unique_build_id).is_empty(), "{device}");
            for &(key, digest) in rewrite.digests {
                assert!(!decode(digest).is_empty(), "{device} {key}");
            }
        }
        // Devices outside the upstream table have no rewrite.
        assert!(baseband_rewrite(&ProductType::from("iPad3,2")).is_none());
        assert!(baseband_rewrite(&ProductType::from("iPhone6,1")).is_none());
    }

    #[test]
    fn rewrites_baseband_entries_of_a_synthetic_manifest() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>BuildIdentities</key><array>
<dict>
    <key>UniqueBuildID</key><data>AAAA</data>
    <key>Manifest</key><dict>
        <key>BasebandFirmware</key><dict>
            <key>SBL1-Version</key><integer>-1560000000</integer>
            <key>RestoreSBL1-Version</key><integer>-1559000000</integer>
            <key>APPS-DownloadDigest</key><data>BBBB</data>
            <key>Info</key><dict><key>Path</key><string>Firmware/Mav5-old.Release.bbfw</string></dict>
        </dict>
        <key>RestoreDeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/dtree.img3</string></dict></dict>
    </dict>
</dict>
</array>
</dict></plist>"#;
        let rewrite = baseband_rewrite(&ProductType::from("iPhone5,1")).unwrap();
        let output =
            rewrite_baseband_manifest(manifest, &rewrite, "Firmware/Mav5-11.80.00.Release.bbfw")
                .unwrap();
        let value = plist::Value::from_reader(std::io::Cursor::new(&output)).unwrap();
        let identity = &value
            .as_dictionary()
            .unwrap()
            .get("BuildIdentities")
            .unwrap()
            .as_array()
            .unwrap()[0];
        let identity = identity.as_dictionary().unwrap();
        assert_eq!(
            identity.get("UniqueBuildID"),
            Some(&plist::Value::Data(decode("IcrFKRzWDvccKDfkfMNPOPYHEV0=")))
        );
        let baseband = identity
            .get("Manifest")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("BasebandFirmware")
            .unwrap()
            .as_dictionary()
            .unwrap();
        assert_eq!(
            baseband.get("RestoreSBL1-Version"),
            Some(&plist::Value::Integer(plist::Integer::from(
                -1_559_114_512_i64
            )))
        );
        assert_eq!(
            baseband.get("SBL1-Version"),
            Some(&plist::Value::Integer(plist::Integer::from(
                -1_560_163_088_i64
            )))
        );
        assert_eq!(
            baseband.get("APPS-DownloadDigest"),
            Some(&plist::Value::Data(decode("2bmJ7Vd+WAmogV+hjq1a86UlBvA=")))
        );
        assert_eq!(
            baseband
                .get("Info")
                .unwrap()
                .as_dictionary()
                .unwrap()
                .get("Path"),
            Some(&plist::Value::String(
                "Firmware/Mav5-11.80.00.Release.bbfw".to_owned()
            ))
        );
        // Non-baseband entries are untouched.
        let tree_path = identity
            .get("Manifest")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("RestoreDeviceTree")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("Info")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("Path")
            .unwrap()
            .as_string()
            .unwrap();
        assert_eq!(tree_path, "Firmware/all_flash/dtree.img3");
    }

    #[test]
    fn rewrite_leaves_identities_without_baseband_alone_except_ubid() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>BuildIdentities</key><array>
<dict>
    <key>UniqueBuildID</key><data>AAAA</data>
    <key>Manifest</key><dict>
        <key>RestoreDeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>dtree.img3</string></dict></dict>
    </dict>
</dict>
</array>
</dict></plist>"#;
        let rewrite = baseband_rewrite(&ProductType::from("iPhone5,2")).unwrap();
        let output =
            rewrite_baseband_manifest(manifest, &rewrite, "Firmware/Mav5-11.80.00.Release.bbfw")
                .unwrap();
        let value = plist::Value::from_reader(std::io::Cursor::new(&output)).unwrap();
        let identity = &value
            .as_dictionary()
            .unwrap()
            .get("BuildIdentities")
            .unwrap()
            .as_array()
            .unwrap()[0];
        let identity = identity.as_dictionary().unwrap();
        // UniqueBuildID is still replaced (upstream's sed hits every identity),
        // but no BasebandFirmware entry is invented.
        assert_eq!(
            identity.get("UniqueBuildID"),
            Some(&plist::Value::Data(decode("lnU0rtBUK6gCyXhEtHuwbEz/IKY=")))
        );
        assert!(
            !identity
                .get("Manifest")
                .unwrap()
                .as_dictionary()
                .unwrap()
                .contains_key("BasebandFirmware")
        );
    }
}
