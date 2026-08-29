//! The OpenAPI specification descriptor and its export to a file.
//!
//! This is where the root [`ApiDoc`] descriptor lives, the one `utoipa` builds
//! the spec from, together with the code that exports it to `docs/openapi.json`.
//! The spec is **committed to the repository** (JWT-59): at runtime it is
//! available at `GET /api-docs/openapi.json`, but while it was not in git a
//! change of the API contract left no trace in the diff — a breaking change
//! could not be spotted in review.
//!
//! The export lives under `#[cfg(test)]` and is done by the
//! `spec_file_is_up_to_date` test: `UPDATE_OPENAPI=1 cargo test openapi`
//! rewrites the file, and an ordinary run compares it against the code. A
//! separate generator binary would also have to be remembered, while the test is
//! already run by CI on every pull request — the file cannot drift from the
//! spec.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

// Imported as a module rather than function by function: `utoipa` takes the
// **text** of the path in `paths(...)` as the tag name that groups endpoints in
// Swagger UI. With `crate::handlers::create_token` the tag would be
// `crate::handlers`.
use crate::handlers;
use crate::models::{
    ErrorResponse, ReadinessResponse, RefreshRequest, RevokeGroupResponse, TokenRequest,
    TokenResponse,
};

/// Path to the exported spec, relative to the repository root.
///
/// Together with the export helpers it is test-only: at runtime the service
/// serves the spec from memory and has no need for the file.
#[cfg(test)]
const SPEC_PATH: &str = "docs/openapi.json";

/// The root descriptor of the OpenAPI documentation.
///
/// It lists the paths (endpoints) and the component schemas `utoipa` generates
/// the OpenAPI specification from. A new endpoint has to be registered here in
/// `paths(...)` and new DTOs in `components(schemas(...))`, or they will not
/// reach the spec. After editing, regenerate the spec file:
/// `UPDATE_OPENAPI=1 cargo test openapi`.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::create_token,
        handlers::verify_token,
        handlers::refresh_token,
        handlers::revoke_token,
        handlers::revoke_subject_tokens,
        handlers::livez,
        handlers::readyz,
        handlers::metrics
    ),
    components(schemas(
        TokenRequest,
        TokenResponse,
        ErrorResponse,
        ReadinessResponse,
        RefreshRequest,
        RevokeGroupResponse
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

/// Registers the security schemes for access levels 2 and 3.
///
/// Level 2 (`proxy_secret`) and level 3 (`totp`) require an `apiKey` header. The
/// header names are the defaults (`X-Proxy-Secret` / `X-TOTP-Code`); when they
/// are overridden through the environment, update the description in the
/// OpenAPI spec too. Level 1 (health, OpenAPI) needs no protection and has no
/// scheme.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // `components` already exists because the schema has registered DTOs.
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "proxy_secret",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-Proxy-Secret",
                    "Level 2: a static secret injected by the reverse proxy. \
                     The proxy MUST strip the client-supplied version of the header.",
                ))),
            );
            components.add_security_scheme(
                "totp",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-TOTP-Code",
                    "Level 3: the current TOTP code (RFC 6238) over the shared secret.",
                ))),
            );
            components.add_security_scheme(
                "metrics_token",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(
                            "Level 4: a static bearer token for scraping /metrics \
                             (AUTH_METRICS_TOKEN).",
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// The absolute path to [`SPEC_PATH`] in the source tree.
///
/// The root comes from `CARGO_MANIFEST_DIR` — a compile-time variable — rather
/// than from the process working directory: cargo runs tests from the root, but
/// relying on that would be unwise.
#[cfg(test)]
fn spec_file() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SPEC_PATH)
}

/// The spec in the form it is stored in the file.
///
/// The format is pretty JSON with a trailing newline: that way the diff in a
/// pull request reads line by line rather than as one long line, and the file is
/// not "nameless" to tools that expect text.
#[cfg(test)]
fn spec_json() -> String {
    let mut json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("the OpenAPI spec does not serialise to JSON");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Paths that are registered but deliberately absent from the spec.
    ///
    /// The spec does not describe itself: the endpoint serving the document is
    /// transport, not part of the API contract. It is an explicit exclusion list
    /// rather than "we silently do not check": any other undocumented endpoint
    /// must fail the test.
    const ROUTES_OUTSIDE_SPEC: &[&str] = &["/api-docs/openapi.json"];

    /// The paths registered in the application, parsed out of the source.
    ///
    /// The approach is crude but honest: a built actix application cannot
    /// enumerate its routes — `ResourceMap` is not exposed, and the "poke a path
    /// and see whether it 404s" approach requires knowing in advance what to
    /// poke, that is, exactly the list we are looking for. So we read the text:
    /// routes in this service are registered by hand with string literals in one
    /// place (`configure_api`), see "Conventions and pitfalls" in `AGENTS.md`.
    ///
    /// Only the body of `configure_api` and the non-test part of `handlers.rs`
    /// are scanned — otherwise the list would pick up routes from the test
    /// applications of neighbouring modules.
    fn registered_routes() -> BTreeSet<&'static str> {
        // The body of `configure_api`: from the signature to the closing brace in
        // column zero. There is no such brace inside the function — the nested
        // blocks are indented.
        let main_rs = include_str!("main.rs");
        let body_start = main_rs
            .find("fn configure_api")
            .expect("configure_api not found in main.rs — the test has fallen behind the code");
        let body = &main_rs[body_start..];
        let body = &body[..body.find("\n}\n").expect("end of configure_api not found") + 1];

        // `handlers.rs` is scanned for the endpoints on actix attribute macros
        // (`#[get("/livez")]`). The test module is cut off: it has its own
        // applications with their own routes.
        let handlers_rs = include_str!("handlers.rs");
        let handlers_rs = &handlers_rs[..handlers_rs
            .find("#[cfg(test)]")
            .unwrap_or(handlers_rs.len())];

        // A nested scope with a non-empty prefix would break the flat parsing:
        // the endpoint path would be assembled from the prefix and the literal.
        // Right now there is exactly one scope and it is empty; should another
        // appear, the test fails rather than lies.
        for prefix in literals_after(body, "web::scope(\"") {
            assert!(
                prefix.is_empty(),
                "web::scope(\"{prefix}\") — a non-empty prefix scope. Route parsing \
                 in this test is flat and such a path would lose the prefix; teach it \
                 to concatenate or rewrite the registration"
            );
        }

        let mut routes = BTreeSet::new();
        for (source, marker) in [
            (body, "web::resource(\""),
            (body, ".route(\""),
            (handlers_rs, "#[get(\""),
            (handlers_rs, "#[post(\""),
            (handlers_rs, "#[put(\""),
            (handlers_rs, "#[patch(\""),
            (handlers_rs, "#[delete(\""),
        ] {
            routes.extend(literals_after(source, marker).filter(|path| !path.is_empty()));
        }

        // A safeguard in case the parsing breaks on a new way of registering
        // routes: an empty (or suspiciously short) list would make the test green
        // forever. The number is deliberately below the current count so that it
        // does not need editing for every new endpoint.
        assert!(
            routes.len() >= 8,
            "route parsing found only {} paths ({routes:?}) — it looks like routes are \
             now registered differently and the test has gone blind",
            routes.len()
        );

        routes
    }

    /// The string literals following each occurrence of `marker`.
    fn literals_after<'a>(
        source: &'a str,
        marker: &'a str,
    ) -> impl Iterator<Item = &'a str> + use<'a> {
        source
            .match_indices(marker)
            .map(move |(at, _)| &source[at + marker.len()..])
            .filter_map(|rest| rest.split_once('"').map(|(literal, _)| literal))
    }

    /// The spec lists every published path — and exactly those.
    ///
    /// The `#[utoipa::path]` annotations live on **generic** handlers (JWT-60):
    /// they can go missing during a refactor silently — the compiler does not
    /// complain, and Swagger UI simply comes up one endpoint short.
    ///
    /// The list of expected paths is **not hard-coded** but parsed out of the
    /// source where the routes are registered. With a manual list the test would
    /// guard itself: a new endpoint would be forgotten both in `ApiDoc` and in
    /// the list, both tests would stay green, and the spec file would be "up to
    /// date" in exactly the sense that it matches an incomplete `ApiDoc`. The
    /// comparison against the file catches edits to the spec; this one catches
    /// the spec drifting from the application.
    #[test]
    fn openapi_spec_lists_all_endpoints() {
        let spec = ApiDoc::openapi();
        let documented: BTreeSet<&str> = spec.paths.paths.keys().map(String::as_str).collect();
        let registered = registered_routes();

        let missing: Vec<&&str> = registered
            .iter()
            .filter(|path| !documented.contains(*path) && !ROUTES_OUTSIDE_SPEC.contains(*path))
            .collect();
        assert!(
            missing.is_empty(),
            "endpoints are registered but did not reach the OpenAPI spec: {missing:?}. \
             They need a #[utoipa::path] annotation on the handler and registration in paths(...) above"
        );

        let stale: Vec<&&str> = documented
            .iter()
            .filter(|path| !registered.contains(*path))
            .collect();
        assert!(
            stale.is_empty(),
            "the spec has paths the application does not: {stale:?}. \
             The endpoint was removed or renamed — remove it from paths(...) above too"
        );
    }

    /// The spec file in the repository matches what the code generates.
    ///
    /// This same test also **exports** the spec: with `UPDATE_OPENAPI=1` it
    /// rewrites the file instead of comparing. One entry point instead of a
    /// "generator plus checker" pair that drifts apart; regeneration is done by
    /// exactly the code that guards freshness in CI.
    ///
    /// Without such a check the export would be dead by construction: the file
    /// would drift from the spec on the very first contract change and the diff
    /// in a pull request would stop meaning anything.
    ///
    /// Note: `info.version` in the spec is the version from `Cargo.toml`, so a
    /// version bump also requires regeneration. Excluding that field was
    /// rejected deliberately: the file in the repository must be exactly what
    /// the service serves, otherwise it is a retelling of the contract rather
    /// than a snapshot of it.
    #[test]
    fn spec_file_is_up_to_date() {
        let path = spec_file();
        let generated = spec_json();

        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, &generated)
                .unwrap_or_else(|e| panic!("could not write {}: {e}", path.display()));
            return;
        }

        let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{} is unreadable ({e}). Export the spec: UPDATE_OPENAPI=1 cargo test openapi",
                path.display()
            )
        });

        // Not `assert_eq!`: it would dump both specs into the report in full
        // (hundreds of lines) and the real difference would drown in them. What
        // exactly changed is visible in `git diff` after regeneration.
        assert!(
            committed == generated,
            "{SPEC_PATH} has drifted from the code. If the API contract changed deliberately \
             (or the version in Cargo.toml was bumped — it goes into info.version), \
             regenerate the file: UPDATE_OPENAPI=1 cargo test openapi"
        );
    }
}
