//! The issuer allowlist (`TOKEN_ISSUER_ALLOWLIST`).
//!
//! The value of the `iss` claim comes from the `Host` header of the request
//! rather than from the configuration (see [`crate::handlers`]). That is
//! convenient — one image serves several domains — but without constraints the
//! client picks `iss` itself. When two instances share one `jwks-service-app`,
//! instance `A` can be made to issue a token with `Host: b.example.com`: the
//! signature is made with the shared key, and instance `B` accepts such a token
//! as its own.
//!
//! The allowlist closes that: when the list is set, a `Host` outside it is
//! rejected. An empty or unset list means the previous behaviour (any `Host`),
//! so that an upgrade does not break existing deployments.
//!
//! The comparison is case-insensitive (host names are case-insensitive) but
//! exact otherwise: the port is part of the value (`example.com` and
//! `example.com:8443` differ), because it is the whole `Host` string that goes
//! into `iss` and is compared against during verification.

use std::env;

use tracing::{info, warn};

/// Name of the environment variable holding the list of allowed `iss` values.
pub const ALLOWLIST_VAR: &str = "TOKEN_ISSUER_ALLOWLIST";

/// Parses the allowlist from the environment: comma-separated values, empty
/// elements skipped, case normalised to lower.
///
/// It is read on every request, like the rest of the token configuration
/// (`TOKEN_EXPIRATION_SECONDS` and its neighbours): the list is short, and we do
/// not keep extra state in the handlers.
fn allowlist() -> Vec<String> {
    parse(&env::var(ALLOWLIST_VAR).unwrap_or_default())
}

/// Parses a raw allowlist value (extracted from [`allowlist`] so that tests do
/// not touch the process-global environment).
fn parse(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Whether `host` is allowed as an `iss`.
///
/// An empty or unset allowlist permits any `Host`.
pub fn is_allowed(host: &str) -> bool {
    allowed_by(&allowlist(), host)
}

/// Check against an already parsed list.
fn allowed_by(allowed: &[String], host: &str) -> bool {
    allowed.is_empty() || allowed.iter().any(|a| a == &host.to_ascii_lowercase())
}

/// Writes a summary of the configuration to the log at startup.
///
/// An unset list is not an error, but it is worth a warning: in a setup with a
/// shared `jwks-service-app` it means tokens can be issued under someone else's
/// name.
pub fn log_summary() {
    let allowed = allowlist();
    if allowed.is_empty() {
        warn!(
            "{ALLOWLIST_VAR} is not set: the iss claim is taken from the Host header without \
             validation. If instances share one jwks-service-app, set the list of allowed issuers."
        );
    } else {
        info!("Allowed issuers (iss): {}", allowed.join(", "));
    }
}

#[cfg(test)]
mod tests {
    //! Parsing and matching are checked on pure functions: the tests never touch
    //! the process-global environment variable, which would otherwise clash with
    //! the HTTP layer tests running in parallel.

    use super::*;

    #[test]
    fn empty_allowlist_allows_any_host() {
        assert!(allowed_by(&parse(""), "example.com"));
        assert!(allowed_by(&parse(""), "evil.example.net"));

        // A list that is set but empty in substance also means "no constraint":
        // otherwise a stray comma in the configuration would silently shut
        // issuing down entirely.
        assert!(allowed_by(&parse(" , ,"), "example.com"));
    }

    #[test]
    fn allowlist_accepts_listed_and_rejects_others() {
        let allowed = parse("a.example.com, b.example.com");
        assert!(allowed_by(&allowed, "a.example.com"));
        assert!(allowed_by(&allowed, "b.example.com"));
        assert!(!allowed_by(&allowed, "c.example.com"));
    }

    #[test]
    fn matching_is_case_insensitive_but_port_sensitive() {
        let allowed = parse("A.Example.COM, b.example.com:8443");
        assert!(allowed_by(&allowed, "a.example.com"));
        assert!(allowed_by(&allowed, "A.EXAMPLE.COM"));
        assert!(allowed_by(&allowed, "b.example.com:8443"));
        // The port is part of the `Host` value, and therefore of `iss`.
        assert!(!allowed_by(&allowed, "a.example.com:8443"));
        assert!(!allowed_by(&allowed, "b.example.com"));
    }
}
