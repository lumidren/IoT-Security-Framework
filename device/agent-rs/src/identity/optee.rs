//! OP-TEE identity backend (cargo feature `optee`, `optee-teec` client API, needs `libteec` at
//! build and run time; compiled in Linux/aarch64 CI only).
//!
//! The keys live in the **IronMesh identity Trusted Application**; the normal world only ever
//! sees public keys, signatures and ECDH outputs.
//!
//! TA UUID: [`TA_UUID`] = `6e1d8a2c-5b3f-4c71-9e0a-1f2b3c4d5e6f`.
//!
//! | Command id | Name            | params (p0 / p1 / p2)                                              | Result |
//! |-----------:|-----------------|---------------------------------------------------------------------|--------|
//! | 0          | `GENERATE_KEY`  | value-in `a = slot` / memref-out 65 B                               | uncompressed P-256 public key |
//! | 1          | `GET_PUBLIC`    | value-in `a = slot` / memref-out 65 B                               | public key (`TEE_ERROR_ITEM_NOT_FOUND` if empty) |
//! | 2          | `SIGN_DIGEST`   | value-in `a = slot` / memref-in 32 B digest / memref-out 64 B       | `r || s` |
//! | 3          | `ECDH`          | value-in `a = slot` / memref-in 65 B peer point / memref-out 32 B   | shared x-coordinate |
//! | 4          | `COMMIT_PENDING`| -                                                                   | pending -> operational (atomic in secure storage) |
//!
//! Slot numbers: 0 bootstrap, 1 operational, 2 pending. Keys are stored in OP-TEE secure storage
//! (`TEE_STORAGE_PRIVATE_REE` or RPMB) bound to the TA. `optee` reports `evidence = null` in v1
//! (`WIRE_FORMAT.md` §4).

use std::sync::{mpsc, Mutex};

use optee_teec::{Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid};
use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

use super::{Assurance, IdentityError, IdentityProvider, KeySlot};
use crate::wire::envelope::{SeType, Tpm2Evidence};

/// UUID of the IronMesh identity TA.
pub const TA_UUID: &str = "6e1d8a2c-5b3f-4c71-9e0a-1f2b3c4d5e6f";
/// `GENERATE_KEY`
pub const CMD_GENERATE_KEY: u32 = 0;
/// `GET_PUBLIC`
pub const CMD_GET_PUBLIC: u32 = 1;
/// `SIGN_DIGEST`
pub const CMD_SIGN_DIGEST: u32 = 2;
/// `ECDH`
pub const CMD_ECDH: u32 = 3;
/// `COMMIT_PENDING`
pub const CMD_COMMIT_PENDING: u32 = 4;

fn slot_id(slot: KeySlot) -> u32 {
    match slot {
        KeySlot::Bootstrap => 0,
        KeySlot::Operational => 1,
        KeySlot::Pending => 2,
    }
}

fn be(e: impl std::fmt::Display) -> IdentityError {
    IdentityError::Backend(e.to_string())
}

enum Req {
    Public(u32, KeySlot, mpsc::Sender<Result<Vec<u8>, IdentityError>>),
    Sign(KeySlot, [u8; 32], mpsc::Sender<Result<Vec<u8>, IdentityError>>),
    Ecdh(KeySlot, Vec<u8>, mpsc::Sender<Result<Vec<u8>, IdentityError>>),
    Commit(mpsc::Sender<Result<Vec<u8>, IdentityError>>),
}

fn run(mut session: Session, rx: mpsc::Receiver<Req>) {
    while let Ok(req) = rx.recv() {
        match req {
            Req::Public(cmd, slot, reply) => {
                let mut out = [0u8; 65];
                let p0 = ParamValue::new(slot_id(slot), 0, ParamType::ValueInput);
                let p1 = ParamTmpRef::new_output(&mut out);
                let mut op = Operation::new(0, p0, p1, ParamNone, ParamNone);
                let r = session.invoke_command(cmd, &mut op).map_err(be).map(|()| op.parameters().1.updated_size());
                let _ = reply.send(r.map(|n| out[..n.min(65)].to_vec()));
            }
            Req::Sign(slot, digest, reply) => {
                let mut out = [0u8; 64];
                let p0 = ParamValue::new(slot_id(slot), 0, ParamType::ValueInput);
                let p1 = ParamTmpRef::new_input(&digest);
                let p2 = ParamTmpRef::new_output(&mut out);
                let mut op = Operation::new(0, p0, p1, p2, ParamNone);
                let r = session.invoke_command(CMD_SIGN_DIGEST, &mut op).map_err(be).map(|()| op.parameters().2.updated_size());
                let _ = reply.send(r.map(|n| out[..n.min(64)].to_vec()));
            }
            Req::Ecdh(slot, peer, reply) => {
                let mut out = [0u8; 32];
                let p0 = ParamValue::new(slot_id(slot), 0, ParamType::ValueInput);
                let p1 = ParamTmpRef::new_input(&peer);
                let p2 = ParamTmpRef::new_output(&mut out);
                let mut op = Operation::new(0, p0, p1, p2, ParamNone);
                let r = session.invoke_command(CMD_ECDH, &mut op).map_err(be).map(|()| op.parameters().2.updated_size());
                let _ = reply.send(r.map(|n| out[..n.min(32)].to_vec()));
            }
            Req::Commit(reply) => {
                let mut op = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
                let _ = reply.send(session.invoke_command(CMD_COMMIT_PENDING, &mut op).map_err(be).map(|()| Vec::new()));
            }
        }
    }
}

/// OP-TEE-backed identity.
pub struct OpteeIdentity {
    device_id: String,
    tenant_id: String,
    tx: Mutex<mpsc::Sender<Req>>,
}

impl OpteeIdentity {
    /// Open a session to the identity TA; ids come from `<dir>/identity.json`.
    ///
    /// # Errors
    /// TEE or I/O errors.
    pub fn open(dir: &std::path::Path) -> Result<Self, IdentityError> {
        let (device_id, tenant_id, _) = super::software::read_identity_ids(dir)?;
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("ironmesh-optee".into())
            .spawn(move || {
                let opened = Context::new().and_then(|mut ctx| {
                    let uuid = Uuid::parse_str(TA_UUID)?;
                    ctx.open_session(uuid)
                });
                match opened {
                    Ok(session) => {
                        let _ = ready_tx.send(Ok(()));
                        run(session, rx);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(be(e)));
                    }
                }
            })
            .map_err(IdentityError::Io)?;
        ready_rx.recv().map_err(be)??;
        Ok(Self { device_id, tenant_id, tx: Mutex::new(tx) })
    }

    fn call(&self, make: impl FnOnce(mpsc::Sender<Result<Vec<u8>, IdentityError>>) -> Req) -> Result<Vec<u8>, IdentityError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.lock().map_err(|_| be("TEE channel poisoned"))?.send(make(reply_tx)).map_err(|_| be("TEE worker stopped"))?;
        reply_rx.recv().map_err(|_| be("TEE worker stopped"))?
    }

    fn pk(bytes: &[u8]) -> Result<p256::PublicKey, IdentityError> {
        p256::PublicKey::from_sec1_bytes(bytes).map_err(|e| IdentityError::Crypto(e.to_string()))
    }
}

impl IdentityProvider for OpteeIdentity {
    fn device_id(&self) -> &str {
        &self.device_id
    }

    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    fn se_type(&self) -> SeType {
        SeType::Optee
    }

    fn assurance(&self) -> Assurance {
        Assurance::Hardware
    }

    fn has_key(&self, slot: KeySlot) -> bool {
        self.public_key(slot).is_ok()
    }

    fn public_key(&self, slot: KeySlot) -> Result<p256::PublicKey, IdentityError> {
        let bytes = self.call(|r| Req::Public(CMD_GET_PUBLIC, slot, r)).map_err(|_| IdentityError::NoKey(slot))?;
        Self::pk(&bytes)
    }

    fn sign(&self, slot: KeySlot, digest: &[u8; 32]) -> Result<[u8; 64], IdentityError> {
        let sig = self.call(|r| Req::Sign(slot, *digest, r))?;
        sig.try_into().map_err(|_| IdentityError::Backend("TA returned a short signature".into()))
    }

    fn ecdh(&self, slot: KeySlot, peer: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        let point = peer.to_sec1_point(false).as_bytes().to_vec();
        let z = Zeroizing::new(self.call(|r| Req::Ecdh(slot, point, r))?);
        let mut out = Zeroizing::new([0u8; 32]);
        if z.len() != 32 {
            return Err(IdentityError::Backend("TA returned a short ECDH output".into()));
        }
        out.copy_from_slice(&z);
        Ok(out)
    }

    fn generate_operational_key(&self) -> Result<p256::PublicKey, IdentityError> {
        Self::pk(&self.call(|r| Req::Public(CMD_GENERATE_KEY, KeySlot::Pending, r))?)
    }

    fn commit_pending(&self) -> Result<(), IdentityError> {
        self.call(Req::Commit).map(|_| ())
    }

    fn generate_bootstrap_key(&self) -> Result<p256::PublicKey, IdentityError> {
        Self::pk(&self.call(|r| Req::Public(CMD_GENERATE_KEY, KeySlot::Bootstrap, r))?)
    }

    fn attestation_evidence(&self, _nonce: &[u8; 32]) -> Result<Option<Tpm2Evidence>, IdentityError> {
        Ok(None)
    }
}
