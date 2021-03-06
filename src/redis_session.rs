use std::io;
use redis::{Client, AsyncCommands, IntoConnectionInfo, RedisError, RedisResult};
use redis::aio::Connection;
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct RedisSessionStore {
    client: Client,
}

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub credentials: String,
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("io error ({0})")]
    Io(io::Error),
    #[error("json deserialization error ({0})")]
    Json(serde_json::Error),
    #[error("redis error ({0})")]
    Redis( #[from] RedisError)
}

impl From<serde_json::Error> for StoreError {
    fn from(err: serde_json::Error) -> StoreError {
        use serde_json::error::Category;
        match err.classify() {
            Category::Io => {
                StoreError::Io(err.into())
            }
            Category::Syntax | Category::Data | Category::Eof => {
                StoreError::Json(err)
            }
        }
    }
}

impl RedisSessionStore {
    pub(crate) async fn get(&self, sid: &str) -> Result<Option<Session>, StoreError> {
        let mut connection = self.connection().await?;
        let session_str: Option<String> = connection.get(sid).await?;
        match session_str {
            Some(json) => Ok(serde_json::from_str(&json)?),
            None => Ok(None)
        }
    }
    pub async fn set(&self, sid: &str, session: Session) -> Result<(), StoreError> {
        let session_str = serde_json::to_string(&session)?;
        let mut connection = self.connection().await?;
        connection.set(sid, session_str).await?;
        Ok(())
    }
    pub fn new(connection_info: impl IntoConnectionInfo) -> RedisResult<Self> {
        Ok(Self {client: Client::open(connection_info)?})
    }
    async fn connection(&self) -> RedisResult<Connection> {
        self.client.get_async_connection().await
    }
    pub async fn clear_store(&self, keys: &[&str]) -> Result<(), StoreError> {
        let mut connection = self.connection().await?;
        for key in keys {
            connection.del(key).await?
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn get_unknown_key() {
        assert!(create_store().await.get("unknown").await.unwrap().is_none())
    }

    #[tokio::test]
    async fn get_session() {
        let store = create_store().await;
        store.set("sid", Session {credentials: String::from("credentials") }).await.unwrap();

        let session = store.get("sid").await.unwrap().unwrap();

        assert_eq!(session.credentials, "credentials");
    }

    async fn create_store() -> RedisSessionStore {
        let store = RedisSessionStore::new("redis://redis/1").unwrap();
        store.clear_store(&["sid"]).await.unwrap();
        store
    }
}