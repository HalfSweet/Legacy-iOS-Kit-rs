//! Apple ID application signing and installation (the AltServer flow).
//!
//! Authenticates with GrandSlam using anisette data from a remote
//! AltServer/SideStore-compatible server, registers the device and the app's
//! App ID with Apple's developer services, downloads the team provisioning
//! profile, re-signs the IPA, and installs it on the device. Credentials are
//! used in memory only and are never persisted.

use std::path::Path;

use legacy_ios_core::Udid;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::{DeviceManager, KitError};

pub use legacy_ios_services::signing::{
    AnisetteData, AnisetteError, AnisetteProvider, DeveloperApiError, DeveloperClient,
    DeveloperSession, DevelopmentCertificate, GsaClient, GsaError, ProvisioningProfile,
    RemoteAnisetteProvider, ResignError, Team, TwoFactorPrompt, read_ipa_bundle_id, resign_ipa,
};

/// Machine name recorded with the submitted development CSR.
const MACHINE_NAME: &str = "Legacy iOS Kit";

/// Parameters for signing and installing an IPA with an Apple ID.
pub struct AppSignRequest {
    /// URL of an AltServer/SideStore-compatible anisette server.
    pub anisette_url: String,
    /// Apple ID (email address).
    pub apple_id: String,
    /// Apple ID password; used in memory only and zeroized on drop.
    pub password: Zeroizing<String>,
    /// Developer team identifier; the first team is used when unset.
    pub team_id: Option<String>,
}

/// Outcome of a successful sign-and-install run.
#[derive(Clone, Debug)]
pub struct AppSignOutcome {
    /// Team the app was signed for.
    pub team_id: String,
    /// Bundle identifier of the installed app.
    pub bundle_id: String,
    /// Whether the device was newly registered with the developer account.
    pub device_registered: bool,
    /// Whether the App ID was newly registered with the developer account.
    pub app_id_registered: bool,
}

impl DeviceManager {
    /// Sign `ipa` with an Apple ID development certificate and install it on
    /// the device. When the account requires trusted-device two-factor
    /// authentication, `two_factor` is called to collect the six-digit code.
    pub async fn sign_and_install_app(
        &self,
        udid: &Udid,
        ipa: &Path,
        request: &AppSignRequest,
        two_factor: TwoFactorPrompt<'_>,
    ) -> Result<AppSignOutcome, KitError> {
        let device = self.find_normal(udid).await?;
        let info = device.query_info().await?;
        let bundle_id = read_ipa_bundle_id(ipa)?;

        let anisette = RemoteAnisetteProvider::new(&request.anisette_url)?
            .fetch()
            .await?;
        let session = GsaClient::new(anisette.clone())
            .authenticate(&request.apple_id, &request.password, two_factor)
            .await?;
        info!("authenticated with the developer services");
        let client = DeveloperClient::new(session, anisette);

        let teams = client.list_teams().await?;
        let team = match &request.team_id {
            Some(identifier) => teams
                .into_iter()
                .find(|team| team.identifier() == identifier)
                .ok_or_else(|| KitError::UnknownDeveloperTeam(identifier.clone()))?,
            None => teams
                .into_iter()
                .next()
                .expect("list_teams rejects empty team lists"),
        };
        info!(team = team.name(), "selected developer team");

        let device_registered = client
            .register_device(&team, info.udid().as_str(), info.device_name())
            .await?;

        let certificate = match client.add_certificate(&team, MACHINE_NAME).await {
            Ok(certificate) => certificate,
            // Free accounts are limited to one development certificate; follow
            // AltServer and revoke the existing certificates, then retry once.
            Err(DeveloperApiError::Apple { .. }) => {
                warn!("development CSR was rejected; revoking existing certificates and retrying");
                for existing in client.list_certificates(&team).await? {
                    client.revoke_certificate(&team, &existing).await?;
                }
                client.add_certificate(&team, MACHINE_NAME).await?
            }
            Err(error) => return Err(error.into()),
        };

        let app_ids = client.list_app_ids(&team).await?;
        let (app_id, app_id_registered) = match app_ids
            .iter()
            .find(|(_, identifier)| identifier == &bundle_id)
        {
            Some((app_id, _)) => (app_id.clone(), false),
            None => (
                client.add_app_id(&team, &bundle_id, &bundle_id).await?,
                true,
            ),
        };
        let profile = client
            .download_team_provisioning_profile(&team, &app_id)
            .await?;

        let work = tempfile::tempdir()?;
        let signed = work.path().join("signed.ipa");
        resign_ipa(ipa, &signed, team.identifier(), &certificate, &profile)?;
        device.install_ipa(&signed).await?;

        Ok(AppSignOutcome {
            team_id: team.identifier().to_owned(),
            bundle_id,
            device_registered,
            app_id_registered,
        })
    }
}
