use plist::{Dictionary, Value};

#[derive(Clone, Debug)]
pub struct RestoreOptions {
    erase: bool,
    update_baseband: bool,
    boot_args: Option<String>,
    system_partition_padding: Dictionary,
    baseband_updater_state: Option<Dictionary>,
    baseband_nonce: Option<Vec<u8>>,
}

impl RestoreOptions {
    pub fn erase() -> Self {
        Self::new(true)
    }

    pub fn update() -> Self {
        Self::new(false)
    }

    fn new(erase: bool) -> Self {
        let mut system_partition_padding = Dictionary::new();
        for (class, size) in [
            ("8", 80_u64),
            ("16", 160_u64),
            ("32", 320_u64),
            ("64", 640_u64),
            ("128", 1280_u64),
        ] {
            system_partition_padding.insert(class.into(), size.into());
        }
        Self {
            erase,
            update_baseband: true,
            boot_args: None,
            system_partition_padding,
            baseband_updater_state: None,
            baseband_nonce: None,
        }
    }

    pub fn without_baseband(mut self) -> Self {
        self.update_baseband = false;
        self
    }

    pub fn with_boot_args(mut self, boot_args: impl Into<String>) -> Self {
        self.boot_args = Some(boot_args.into());
        self
    }

    pub fn with_system_partition_padding(mut self, padding: Dictionary) -> Self {
        self.system_partition_padding = padding;
        self
    }

    pub fn with_baseband_preflight(
        mut self,
        updater_state: Dictionary,
        nonce: Option<Vec<u8>>,
    ) -> Self {
        self.baseband_updater_state = Some(updater_state);
        self.baseband_nonce = nonce;
        self
    }

    pub fn to_dictionary(&self) -> Dictionary {
        let mut options = Dictionary::new();
        options.insert(
            "AuthInstallRestoreBehavior".into(),
            behavior(self.erase).into(),
        );
        options.insert("AutoBootDelay".into(), 0_u64.into());
        options.insert("BootImageType".into(), "UserOrInternal".into());
        options.insert("CreateFilesystemPartitions".into(), true.into());
        options.insert("DFUFileType".into(), "RELEASE".into());
        options.insert("DataImage".into(), false.into());
        options.insert("FirmwareDirectory".into(), ".".into());
        options.insert("FlashNOR".into(), true.into());
        options.insert("KernelCacheType".into(), "Release".into());
        options.insert("NORImageType".into(), "production".into());
        options.insert("RestoreBundlePath".into(), "/tmp/Per2.tmp".into());
        options.insert("RootToInstall".into(), false.into());
        options.insert("SystemImage".into(), true.into());
        options.insert("SystemImageType".into(), "User".into());
        options.insert(
            "SystemPartitionPadding".into(),
            self.system_partition_padding.clone().into(),
        );
        options.insert(
            "UUID".into(),
            uuid::Uuid::new_v4().to_string().to_uppercase().into(),
        );
        options.insert("UpdateBaseband".into(), self.update_baseband.into());
        options.insert("PersonalizedDuringPreflight".into(), true.into());
        options.insert("SupportedDataTypes".into(), supported_data_types().into());
        options.insert(
            "SupportedMessageTypes".into(),
            supported_message_types().into(),
        );
        if let Some(boot_args) = &self.boot_args {
            options.insert("RestoreBootArgs".into(), boot_args.clone().into());
        }
        if let Some(updater_state) = &self.baseband_updater_state {
            options.insert("BBUpdaterState".into(), updater_state.clone().into());
        }
        if let Some(nonce) = &self.baseband_nonce {
            options.insert("BasebandNonce".into(), Value::Data(nonce.clone()));
        }
        options
    }
}

fn supported_data_types() -> Dictionary {
    capability_dictionary(&[
        ("AuthInstallCACert", true),
        ("BasebandBootData", false),
        ("BasebandData", false),
        ("BasebandStackData", false),
        ("BasebandUpdaterOutputData", false),
        ("BootabilityBundle", false),
        ("BootabilityBundleV2", false),
        ("BuildIdentityDict", false),
        ("BuildIdentityDictV2", false),
        ("Cryptex1LocalPolicy", true),
        ("DataType", false),
        ("DeviceRestoreInfoPreflight", false),
        ("DiagData", false),
        ("EANData", false),
        ("FDRMemoryCommit", false),
        ("FDRTrustData", false),
        ("FUDData", false),
        ("FileData", false),
        ("FileDataDone", false),
        ("FirmwareUpdaterData", false),
        ("FirmwareUpdaterDataV2", false),
        ("FirmwareUpdaterDataV3", true),
        ("FirmwareUpdaterPreflight", true),
        ("GrapeFWData", false),
        ("HPMFWData", false),
        ("HostSystemTime", true),
        ("KernelCache", false),
        ("MessageUseStreamedImageFile", true),
        ("NORData", false),
        ("NitrogenFWData", true),
        ("OpalFWData", false),
        ("OverlayRootDataCount", false),
        ("OverlayRootDataForKey", true),
        ("OverlayRootDataForKeyIndex", true),
        ("PeppyFWData", true),
        ("PersonalizedBootObjectV3", false),
        ("PersonalizedData", true),
        ("ProvisioningData", false),
        ("RamdiskFWData", true),
        ("ReceiptManifest", true),
        ("RecoveryOSASRImage", true),
        ("RecoveryOSAppleLogo", true),
        ("RecoveryOSDeviceTree", true),
        ("RecoveryOSFileAssetImage", true),
        ("RecoveryOSIBEC", true),
        ("RecoveryOSIBootFWFilesImages", true),
        ("RecoveryOSImage", true),
        ("RecoveryOSKernelCache", true),
        ("RecoveryOSLocalPolicy", true),
        ("RecoveryOSOverlayRootDataCount", false),
        ("RecoveryOSRootTicketData", true),
        ("RecoveryOSStaticTrustCache", true),
        ("RecoveryOSVersionData", true),
        ("RestoreLocalPolicy", true),
        ("RootData", false),
        ("RootTicket", false),
        ("S3EOverride", false),
        ("SourceBootObjectV3", false),
        ("SourceBootObjectV4", false),
        ("SourceBootObjectV5", false),
        ("SsoServiceTicket", false),
        ("StockholmPostflight", false),
        ("SystemImageCanonicalMetadata", false),
        ("SystemImageData", false),
        ("SystemImageRootHash", false),
        ("URLAsset", true),
        ("USBCFWData", false),
        ("USBCOverride", false),
        ("UpdateVolumeOverlayRootDataCount", true),
    ])
}

fn supported_message_types() -> Dictionary {
    capability_dictionary(&[
        ("AsyncDataRequestMsg", true),
        ("AsyncWait", true),
        ("BBUpdateStatusMsg", false),
        ("CheckpointMsg", true),
        ("CrashLog", true),
        ("DataRequestMsg", false),
        ("FDRSubmit", true),
        ("MsgType", false),
        ("PreviousRestoreLogMsg", false),
        ("ProgressMsg", false),
        ("ProvisioningAck", false),
        ("ProvisioningInfo", false),
        ("ProvisioningStatusMsg", false),
        ("ReceivedFinalStatusMsg", false),
        ("RestoreAttestation", true),
        ("RestoreProtocol", true),
        ("RestoredCrash", true),
        ("StatusMsg", false),
    ])
}

fn capability_dictionary(entries: &[(&str, bool)]) -> Dictionary {
    entries
        .iter()
        .map(|(name, value)| ((*name).to_owned(), Value::Boolean(*value)))
        .collect()
}

const fn behavior(erase: bool) -> &'static str {
    if erase { "Erase" } else { "Update" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_erase_options_without_baseband() {
        let options = RestoreOptions::erase().without_baseband().to_dictionary();

        assert_eq!(
            options
                .get("AuthInstallRestoreBehavior")
                .and_then(Value::as_string),
            Some("Erase")
        );
        assert_eq!(
            options.get("UpdateBaseband").and_then(Value::as_boolean),
            Some(false)
        );
        assert_eq!(
            options
                .get("PersonalizedDuringPreflight")
                .and_then(Value::as_boolean),
            Some(true)
        );
        let data_types = options
            .get("SupportedDataTypes")
            .and_then(Value::as_dictionary)
            .unwrap();
        assert_eq!(
            data_types
                .get("FirmwareUpdaterDataV3")
                .and_then(Value::as_boolean),
            Some(true)
        );
        let message_types = options
            .get("SupportedMessageTypes")
            .and_then(Value::as_dictionary)
            .unwrap();
        assert_eq!(
            message_types
                .get("DataRequestMsg")
                .and_then(Value::as_boolean),
            Some(false)
        );
    }
}
