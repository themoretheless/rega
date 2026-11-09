//! PostgreSQL [`AccountStore`] built on `sqlx` (feature `postgres`).

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::{AccountStore, ExternalLogin, NewUser, ProviderId, StoreError};

/// Schema applied by [`PgAccountStore::migrate`]; also shipped as
/// `migrations/0001_rega.sql` for external migration tools.
pub const SCHEMA: &str = include_str!("../migrations/0001_rega.sql");

/// [`AccountStore`] backed by the `rega_users` / `rega_logins` tables.
#[derive(Debug, Clone)]
pub struct PgAccountStore {
    pool: PgPool,
}

impl PgAccountStore {
    /// Wraps an existing pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates the tables and indexes if they do not exist.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::raw_sql(SCHEMA)
            .execute(&self.pool)
            .await
            .map_err(other)?;
        Ok(())
    }

    /// The underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn other(e: sqlx::Error) -> StoreError {
    StoreError::Other(Box::new(e))
}

#[async_trait]
impl AccountStore for PgAccountStore {
    type UserId = i64;

    async fn find_by_login(&self, login: &ExternalLogin) -> Result<Option<i64>, StoreError> {
        let row =
            sqlx::query("SELECT user_id FROM rega_logins WHERE provider = $1 AND subject = $2")
                .bind(login.provider.as_str())
                .bind(&login.subject)
                .fetch_optional(&self.pool)
                .await
                .map_err(other)?;
        Ok(row.map(|r| r.get::<i64, _>(0)))
    }

    async fn find_by_verified_email(&self, email: &str) -> Result<Option<i64>, StoreError> {
        let row = sqlx::query(
            "SELECT id FROM rega_users WHERE email_verified AND lower(email) = lower($1) ORDER BY id LIMIT 1",
        )
        .bind(email.trim())
        .fetch_optional(&self.pool)
        .await
        .map_err(other)?;
        Ok(row.map(|r| r.get::<i64, _>(0)))
    }

    async fn register(&self, user: NewUser, login: ExternalLogin) -> Result<i64, StoreError> {
        // One transaction: a concurrent registration of the same login blocks on
        // the primary key, then sees the conflict and rolls its user back.
        let mut tx = self.pool.begin().await.map_err(other)?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO rega_users (email, email_verified, name, avatar_url) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(&user.name)
        .bind(&user.avatar_url)
        .fetch_one(&mut *tx)
        .await
        .map_err(other)?;
        let inserted = sqlx::query(
            "INSERT INTO rega_logins (provider, subject, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(login.provider.as_str())
        .bind(&login.subject)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(other)?
        .rows_affected();
        if inserted == 0 {
            tx.rollback().await.map_err(other)?;
            return Err(StoreError::Conflict);
        }
        tx.commit().await.map_err(other)?;
        Ok(id)
    }

    async fn add_login(&self, user: &i64, login: ExternalLogin) -> Result<(), StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO rega_logins (provider, subject, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(login.provider.as_str())
        .bind(&login.subject)
        .bind(*user)
        .execute(&self.pool)
        .await
        .map_err(other)?
        .rows_affected();
        if inserted == 0 {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    async fn remove_login(&self, user: &i64, login: &ExternalLogin) -> Result<bool, StoreError> {
        let removed = sqlx::query(
            "DELETE FROM rega_logins WHERE provider = $1 AND subject = $2 AND user_id = $3",
        )
        .bind(login.provider.as_str())
        .bind(&login.subject)
        .bind(*user)
        .execute(&self.pool)
        .await
        .map_err(other)?
        .rows_affected();
        Ok(removed > 0)
    }

    async fn logins(&self, user: &i64) -> Result<Vec<ExternalLogin>, StoreError> {
        let rows = sqlx::query(
            "SELECT provider, subject FROM rega_logins WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(*user)
        .fetch_all(&self.pool)
        .await
        .map_err(other)?;
        rows.into_iter()
            .map(|r| {
                let provider: String = r.get(0);
                Ok(ExternalLogin {
                    provider: ProviderId::new(provider),
                    subject: r.get(1),
                })
            })
            .collect()
    }
}
