use base64::DecodeError;
use jwt::Error as JwtError;
use hyper::header::ToStrError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthProxyError {
    #[error("cannot decode base64 ({0})")]
    B64DecodeError(#[from] DecodeError),
    #[error("cannot decode jwt token ({0})")]
    JwtError(#[from] JwtError),
    #[error("no cookies header")]
    NoCookiesHeader(),
    #[error("no auth cookie")]
    NoAuthorizationCookie(),
    #[error("string error ({0})")]
    StrError(#[from] ToStrError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

