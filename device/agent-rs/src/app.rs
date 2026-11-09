//! Wiring from [`Settings`] to the identity backend, boot control and agent options (shared by
//! the service binary, the DUT channel and the tests).

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::agent::{AgentEvent, AgentOptions, RebootReason};
use crate::identity::software::{SecretSource, SoftwareIdentity};
use crate::identity::{IdentityError, SharedIdentity};
use crate::ota::boot::{BootControl, FileBootControl, FwSetenvBootControl};
use crate::seq::Clock;
use crate::settings::{Backend, Settings};
use crate::telemetry::{StaticTelemetry, SystemTelemetry, TelemetrySource};

/// The software backend's secret source for these settings.
#[must_use]
pub fn secret_source(s: &Settings) -> SecretSource {
    #[cfg(feature = "keyring")]
    if s.identity.use_keyring {
        return SecretSource::FileAndKeyring(s.identity.machine_secret.clone());
    }
    SecretSource::File(s.identity.machine_secret.clone())
}

/// Open the configured identity backend.
///
/// # Errors
/// Backend errors, or a backend that is not compiled in.
pub fn open_identity(s: &Settings) -> Result<SharedIdentity, IdentityError> {
    match s.identity.backend {
        Backend::Software => Ok(Arc::new(SoftwareIdentity::open(&s.identity.dir, &secret_source(s))?)),
        #[cfg(feature = "tpm")]
        Backend::Tpm => Ok(Arc::new(crate::identity::tpm::TpmIdentity::open(crate::identity::tpm::TpmConfig {
            tcti: s.identity.tpm_tcti.clone(),
            primary_handle: s.identity.tpm_primary_handle,
            dir: s.identity.dir.clone(),
            ak_cert_path: s.identity.ak_cert.clone(),
        })?)),
        #[cfg(not(feature = "tpm"))]
        Backend::Tpm => Err(IdentityError::Backend("this build has no TPM support (cargo feature `tpm`)".into())),
        #[cfg(feature = "optee")]
        Backend::Optee => Ok(Arc::new(crate::identity::optee::OpteeIdentity::open(&s.identity.dir)?)),
        #[cfg(not(feature = "optee"))]
        Backend::Optee => Err(IdentityError::Backend("this build has no OP-TEE support (cargo feature `optee`)".into())),
    }
}

/// Create the identity directory for a new device (factory mode).
///
/// # Errors
/// Backend errors.
pub fn create_identity(s: &Settings, device_id: &str, tenant_id: &str) -> Result<SharedIdentity, IdentityError> {
    match s.identity.backend {
        Backend::Software => Ok(Arc::new(SoftwareIdentity::create(&s.identity.dir, device_id, tenant_id, &secret_source(s))?)),
        Backend::Tpm => {
            crate::identity::software::write_identity_ids(&s.identity.dir, device_id, tenant_id, crate::wire::envelope::SeType::Tpm2)?;
            open_identity(s)
        }
        Backend::Optee => {
            crate::identity::software::write_identity_ids(&s.identity.dir, device_id, tenant_id, crate::wire::envelope::SeType::Optee)?;
            open_identity(s)
        }
    }
}

/// The configured boot control.
#[must_use]
pub fn boot_control(s: &Settings) -> Arc<dyn BootControl> {
    match s.ota.boot_control.as_str() {
        "fw_setenv" => Arc::new(FwSetenvBootControl::detect(s.ota.max_boot_attempts)),
        _ => Arc::new(FileBootControl::new(&s.ota.slots_dir, s.ota.max_boot_attempts)),
    }
}

/// Agent options for these settings.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn agent_options(
    s: &Settings,
    identity: SharedIdentity,
    clock: Arc<Clock>,
    events: broadcast::Sender<AgentEvent>,
    boot_reason: Option<RebootReason>,
    auto_connect: bool,
    net_up: bool,
    synthetic_telemetry: bool,
) -> AgentOptions {
    let telemetry: Box<dyn TelemetrySource> = if synthetic_telemetry {
        Box::new(StaticTelemetry::default())
    } else {
        Box::new(SystemTelemetry::new(s.telemetry.auth_log.clone()))
    };
    AgentOptions { settings: s.clone(), identity, boot: boot_control(s), telemetry, clock, events, boot_reason, auto_connect, net_up }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiring() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Settings::default();
        s.rebase(dir.path());
        assert!(open_identity(&s).is_err());
        let id = create_identity(&s, "dev-0000000000000001", "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11").unwrap();
        assert_eq!(id.device_id(), "dev-0000000000000001");
        assert!(open_identity(&s).is_ok());
        s.identity.backend = Backend::Tpm;
        #[cfg(not(feature = "tpm"))]
        assert!(open_identity(&s).is_err());
        s.identity.backend = Backend::Optee;
        #[cfg(not(feature = "optee"))]
        assert!(open_identity(&s).is_err());
        let _ = boot_control(&s);
        s.ota.boot_control = "fw_setenv".into();
        let _ = boot_control(&s);
        let (tx, _) = broadcast::channel(4);
        let o = agent_options(&s, id, Arc::new(Clock::new()), tx, None, false, true, true);
        assert!(!o.auto_connect);
    }
}
