use actix_web::web::Data;
use crate::models::jwt::{JsonWebToken, JtiStore, JwtError, TokenClaims, TokenHeaders};
use crate::key::KeyManager;

pub struct JwtManager;

impl JwtManager {
    pub async fn generate_token<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<String, JwtError> {
        let (jwk, private_key) = key_manager.get_private_key().await.unwrap();

        let claims = TokenClaims::create_new(
            issuer,
            subject,
            audience,
            store,
        ).await?;

        let headers = TokenHeaders::create_new(jwk.kid);

        let token = JsonWebToken::create_new(
            headers,
            claims,
            private_key,
        );

        Ok(token.to_string())
    }

    pub async fn verify_token<T: JtiStore>(
        token: &str,
        issuer: &str,
        audience: &str,
        store: Data<T>,
    ) -> Result<TokenClaims, JwtError> {
        match JsonWebToken::from_string(token, issuer, audience, store).await {
            Ok(jwt) => Ok(jwt.claims),
            Err(e) => Err(e),
        }
    }
}