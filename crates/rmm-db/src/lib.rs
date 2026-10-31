//! Database access layer: pool, migrations, scoped transactions and repositories.

pub mod repo;
pub mod scope;

use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Name of the Postgres schema owned by the platform.
pub const SCHEMA: &str = "rmm";

/// How long [`connect`] keeps retrying before giving up.
const CONNECT_DEADLINE: Duration = Duration::from_secs(30);

/// Errors from the database layer.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A query or connection failed.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Applying migrations failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A role name failed validation.
    #[error("invalid role name: {0}")]
    InvalidRole(String),
}

/// Connect to Postgres, retrying for up to 30 seconds.
pub async fn connect(url: &str) -> Result<PgPool, DbError> {
    let start = Instant::now();
    loop {
        let attempt = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url)
            .await;
        match attempt {
            Ok(pool) => return Ok(pool),
            Err(err) if start.elapsed() >= CONNECT_DEADLINE => return Err(err.into()),
            Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
}

/// Apply all pending migrations.
pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Run `select 1` and return the result.
pub async fn ping(pool: &PgPool) -> Result<i32, DbError> {
    let one = sqlx::query_scalar!(r#"select 1::int4 as "one!""#)
        .fetch_one(pool)
        .await?;
    Ok(one)
}

#[cfg(test)]
mod tests {
    #[test]
    fn schema_name() {
        assert_eq!(super::SCHEMA, "rmm");
    }
}
