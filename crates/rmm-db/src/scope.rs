//! Scoped transactions: every repository call runs inside one of these so
//! that row level security sees the caller's client scope.

use sqlx::postgres::PgPoolOptions;
use sqlx::types::Uuid;
use sqlx::{PgPool, Postgres, Transaction};

use crate::DbError;

/// Which rows a transaction may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Only rows belonging to these clients (empty sees nothing).
    Clients(Vec<Uuid>),
    /// Trusted service access to all clients, with a static reason.
    Service(&'static str),
}

/// Begin a transaction with the scope and actor applied for its lifetime.
pub async fn begin_scoped(
    pool: &PgPool,
    scope: &Scope,
    actor: &str,
) -> Result<Transaction<'static, Postgres>, DbError> {
    let mut tx = pool.begin().await?;
    match scope {
        Scope::Clients(ids) => {
            let literal = format!(
                "{{{}}}",
                ids.iter()
                    .map(Uuid::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            sqlx::query("select set_config('rmm.client_ids', $1, true), set_config('rmm.service', 'off', true)")
                .bind(literal)
                .execute(&mut *tx)
                .await?;
        }
        Scope::Service(reason) => {
            sqlx::query("select set_config('rmm.service', 'on', true), set_config('rmm.service_reason', $1, true)")
                .bind(*reason)
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("select set_config('rmm.actor', $1, true)")
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Whether `role` is an acceptable role identifier (`[a-z_]+`).
fn valid_role(role: &str) -> bool {
    !role.is_empty() && role.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// Connect and run `SET ROLE <role>` on every new connection.
pub async fn connect_as(url: &str, role: &str) -> Result<PgPool, DbError> {
    if !valid_role(role) {
        return Err(DbError::InvalidRole(role.to_owned()));
    }
    let stmt = format!("SET ROLE {role}");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(move |conn, _meta| {
            let stmt = stmt.clone();
            Box::pin(async move {
                sqlx::query(&stmt).execute(&mut *conn).await?;
                Ok(())
            })
        })
        .connect(url)
        .await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::valid_role;

    #[test]
    fn role_validation() {
        assert!(valid_role("rmm_api"));
        assert!(!valid_role(""));
        assert!(!valid_role("rmm-api"));
        assert!(!valid_role("rmm_api; drop"));
        assert!(!valid_role("Rmm"));
    }
}
