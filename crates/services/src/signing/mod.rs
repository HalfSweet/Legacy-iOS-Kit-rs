//! Apple ID application signing (the AltServer/PlumeSign flow).
//!
//! Authenticates an Apple ID against GrandSlam, registers the device and an
//! App ID with Apple's developer services, downloads a team provisioning
//! profile, and re-signs an IPA with the issued development certificate so it
//! can be installed on the registered device.
//!
//! Anisette headers cannot be generated locally without Apple's
//! non-redistributable ADI library, so they are fetched from a configurable
//! AltServer/SideStore-compatible anisette server.

mod anisette;
mod developer_api;
mod gsa;
mod resign;
mod srp;

pub use anisette::{AnisetteData, AnisetteError, AnisetteProvider, RemoteAnisetteProvider};
pub use developer_api::{
    DeveloperApiError, DeveloperClient, DevelopmentCertificate, ProvisioningProfile, Team,
};
pub use gsa::{DeveloperSession, GsaClient, GsaError, TwoFactorPrompt};
pub use resign::{ResignError, read_ipa_bundle_id, resign_ipa};
