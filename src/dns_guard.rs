//! dns_guard — WFP filter *specs*. [DONE] for construction.
//! Actual `FwpmEngineOpen0` / callout-driver redirect remain STUB: a
//! signed kernel callout is out of scope for a user-mode crate.

use crate::error::DpiGuardError;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterSpec {
    pub name: &'static str,
    pub layer: &'static str,
    pub action_block: bool,
    pub remote_port: Option<u16>,
    pub remote_addr: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpSessionSpec {
    pub session_name: &'static str,
    pub dynamic: bool,
}

pub fn init_wfp_hook_spec() -> WfpSessionSpec {
    WfpSessionSpec {
        session_name: "dpi_guard_dns_protect",
        dynamic: true,
    }
}

/// Allow UDP/53 to 127.0.0.1 (must be installed at higher priority than the block).
pub fn allow_port_53_localhost_spec() -> WfpFilterSpec {
    WfpFilterSpec {
        name: "allow-dns-localhost",
        layer: "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        action_block: false,
        remote_port: Some(53),
        remote_addr: Some(Ipv4Addr::LOCALHOST),
    }
}

/// Block UDP/53 to any remote address.
pub fn block_port_53_spec() -> WfpFilterSpec {
    WfpFilterSpec {
        name: "block-dns",
        layer: "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        action_block: true,
        remote_port: Some(53),
        remote_addr: None,
    }
}

/// The pair WFP actually needs: allow localhost, then block the rest.
pub fn dns_protection_filters() -> Vec<WfpFilterSpec> {
    vec![allow_port_53_localhost_spec(), block_port_53_spec()]
}

/// Back-compat name: the *block* half of the pair.
pub fn block_port_53_except_localhost_spec() -> WfpFilterSpec {
    block_port_53_spec()
}

pub fn block_port_53_except_localhost() -> Result<(), DpiGuardError> {
    #[cfg(windows)]
    {
        Err(DpiGuardError::Driver(
            "WFP FFI bindings not implemented in this build".into(),
        ))
    }
    #[cfg(not(windows))]
    {
        Err(DpiGuardError::PlatformNotSupported {
            os: std::env::consts::OS,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHijackSpec {
    pub trusted_resolver: Ipv4Addr,
    /// Packet redirect needs a signed WFP callout driver — not this crate.
    pub needs_callout_driver: bool,
}

pub fn hijack_dns_requests_target(trusted_resolver: Ipv4Addr) -> Result<Ipv4Addr, DpiGuardError> {
    hijack_dns_requests_spec(trusted_resolver).map(|s| s.trusted_resolver)
}

pub fn hijack_dns_requests_spec(trusted_resolver: Ipv4Addr) -> Result<DnsHijackSpec, DpiGuardError> {
    if trusted_resolver.is_loopback() || trusted_resolver.is_unspecified() {
        return Err(DpiGuardError::OutOfRange(
            "trusted resolver must be a real routable address".into(),
        ));
    }
    Ok(DnsHijackSpec {
        trusted_resolver,
        needs_callout_driver: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_is_dynamic_for_crash_safety() {
        assert!(init_wfp_hook_spec().dynamic);
    }

    #[test]
    fn protection_is_two_rules_allow_then_block() {
        let rules = dns_protection_filters();
        assert_eq!(rules.len(), 2);
        assert!(!rules[0].action_block);
        assert_eq!(rules[0].remote_addr, Some(Ipv4Addr::LOCALHOST));
        assert!(rules[1].action_block);
        assert_eq!(rules[1].remote_port, Some(53));
    }

    #[test]
    fn hijack_rejects_loopback_and_unspecified_targets() {
        assert!(hijack_dns_requests_target(Ipv4Addr::LOCALHOST).is_err());
        assert!(hijack_dns_requests_target(Ipv4Addr::UNSPECIFIED).is_err());
        let spec = hijack_dns_requests_spec(Ipv4Addr::new(1, 1, 1, 1)).unwrap();
        assert!(spec.needs_callout_driver);
    }
}
