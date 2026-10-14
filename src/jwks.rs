//! `id_token` signature verification against a provider's JSON Web Key Set.

use std::collections::HashMap;
use std::sync::RwLock;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation};

use crate::apple::now;
use crate::client::read_json;
use crate::{Error, Provider, Result};

/// Do not refetch a key set more often than this (protects against `kid`
/// spraying forcing a request per token).
const MIN_REFRESH_SECS: u64 = 60;
/// Refetch key sets at least this often to pick up rotations.
const MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Cached key set of one provider.
#[derive(Debug)]
pub(crate) struct Jwks {
    url: String,
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    keys: HashMap<String, (DecodingKey, jsonwebtoken::Algorithm)>,
    fetched_at: u64,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("kids", &self.keys.len())
            .finish()
    }
}

impl Jwks {
    pub(crate) fn new(url: String) -> Self {
        Self {
            url,
            state: RwLock::default(),
        }
    }

    /// Verifies signature, issuer, audience, expiry and (optionally) nonce.
    pub(crate) async fn verify(
        &self,
        http: &reqwest::Client,
        provider: Provider,
        id_token: &str,
        client_id: &str,
        nonce: Option<&str>,
    ) -> Result<serde_json::Value> {
        let header = jsonwebtoken::decode_header(id_token)?;
        let kid = header
            .kid
            .ok_or_else(|| Error::IdToken("token has no kid".into()))?;

        let (key, alg) = match self.lookup(&kid, false) {
            Some(found) => found,
            None => {
                self.refresh(http).await?;
                self.lookup(&kid, true)
                    .ok_or_else(|| Error::IdToken(format!("unknown signing key `{kid}`")))?
            }
        };
        if alg != header.alg {
            return Err(Error::IdToken(
                "algorithm does not match the signing key".into(),
            ));
        }

        let mut validation = Validation::new(alg);
        validation.set_audience(&[client_id]);
        validation.leeway = 60;
        let issuers = provider.issuers();
        if !issuers.is_empty() {
            validation.set_issuer(issuers);
        }
        let claims = jsonwebtoken::decode::<serde_json::Value>(id_token, &key, &validation)?.claims;

        if provider == Provider::Microsoft {
            // Multi-tenant issuer: https://login.microsoftonline.com/{tid}/v2.0
            let tid = claims["tid"].as_str().unwrap_or_default();
            let expected = format!("https://login.microsoftonline.com/{tid}/v2.0");
            if tid.is_empty() || claims["iss"].as_str() != Some(expected.as_str()) {
                return Err(Error::IdToken("unexpected issuer".into()));
            }
        }
        if let Some(nonce) = nonce {
            if claims["nonce"].as_str() != Some(nonce) {
                return Err(Error::IdToken("nonce mismatch".into()));
            }
        }
        Ok(claims)
    }

    fn lookup(
        &self,
        kid: &str,
        after_refresh: bool,
    ) -> Option<(DecodingKey, jsonwebtoken::Algorithm)> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        if !after_refresh && now().saturating_sub(state.fetched_at) > MAX_AGE_SECS {
            return None;
        }
        state.keys.get(kid).cloned()
    }

    async fn refresh(&self, http: &reqwest::Client) -> Result<()> {
        {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            let fresh = now().saturating_sub(state.fetched_at) < MIN_REFRESH_SECS;
            if fresh && !state.keys.is_empty() {
                return Ok(());
            }
        }
        let json = read_json(http.get(&self.url).send().await?).await?;
        let set: JwkSet = serde_json::from_value(json)?;
        let keys = set
            .keys
            .iter()
            .filter_map(|jwk| {
                let kid = jwk.common.key_id.clone()?;
                let alg = jwk
                    .common
                    .key_algorithm
                    .and_then(|a| a.to_string().parse().ok())
                    .unwrap_or(match jwk.algorithm {
                        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(_) => {
                            jsonwebtoken::Algorithm::ES256
                        }
                        _ => jsonwebtoken::Algorithm::RS256,
                    });
                let key = DecodingKey::from_jwk(jwk).ok()?;
                Some((kid, (key, alg)))
            })
            .collect();
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.keys = keys;
        state.fetched_at = now();
        Ok(())
    }
}
