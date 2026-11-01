//! Database access layer: pool, migrations, scoped transactions and repositories.

pub mod actions;
pub mod repo;
pub mod scope;
pub mod telemetry;

use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

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

/// Connection options for `url` with `search_path` pinned to `public`.
///
/// The platform owns a schema named `rmm`, and the default search path is
/// `"$user", public`. When the database user is also called `rmm`, unqualified
/// names (sqlx's `_sqlx_migrations`) would resolve to `public` before the
/// schema exists and to `rmm` afterwards, so migrations re-ran on every start.
/// Platform queries always schema-qualify their tables.
pub(crate) fn connect_options(url: &str) -> Result<PgConnectOptions, DbError> {
    let opts: PgConnectOptions = url.parse()?;
    Ok(opts.options([("search_path", "public")]))
}

/// Connect to Postgres, retrying for up to 30 seconds.
pub async fn connect(url: &str) -> Result<PgPool, DbError> {
    let opts = connect_options(url)?;
    let start = Instant::now();
    loop {
        let attempt = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts.clone())
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
