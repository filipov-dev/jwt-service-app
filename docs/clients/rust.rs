// Rust — библиотеки: totp-rs, reqwest (`cargo add totp-rs reqwest tokio -F reqwest/json,tokio/full`)
use totp_rs::{Algorithm, Secret, TOTP};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = std::env::var("AUTH_TOTP_SECRET")?; // base32
    let service = std::env::var("JWT_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8080".into());

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, Secret::Encoded(secret).to_bytes()?)?;
    let code = totp.generate_current()?;

    let resp = reqwest::Client::new()
        .post(format!("{service}/tokens"))
        .header("X-TOTP-Code", code)
        .header("Host", "example.com")
        .json(&serde_json::json!({ "sub": "svc-a", "aud": ["svc-b"] }))
        .send()
        .await?;
    println!("{}", resp.status());
    Ok(())
}
