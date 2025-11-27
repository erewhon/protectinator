//! CLI command implementations

#[cfg(feature = "fim")]
pub mod fim;
#[cfg(feature = "hardening")]
pub mod harden;
pub mod info;
#[cfg(feature = "persistence")]
pub mod persistence;
#[cfg(feature = "privesc")]
pub mod privesc;
#[cfg(feature = "procmon")]
pub mod procmon;
pub mod scan;
#[cfg(feature = "sigma")]
pub mod sigma;
#[cfg(feature = "osverify")]
pub mod verify;
#[cfg(feature = "yara")]
pub mod yara;
