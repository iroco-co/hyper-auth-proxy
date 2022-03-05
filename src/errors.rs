use base64::DecodeError;
use jwt::Error as JwtError;
use hyper::header::ToStrError;

pub enum AuthProxyError {
    DecodeError(DecodeError),
    JwtError(JwtError),
    NoCookiesHeader(),
    NoAuthorizationCookie(),
    StrError(ToStrError)
}

impl From<DecodeError> for AuthProxyError {
    fn from(err: DecodeError) -> AuthProxyError {
        AuthProxyError::DecodeError(err)
    }
}

impl From<ToStrError> for AuthProxyError {
    fn from(err: ToStrError) -> AuthProxyError {
        AuthProxyError::StrError(err)
    }
}

impl From<JwtError> for AuthProxyError {
    fn from(err: JwtError) -> AuthProxyError {
        AuthProxyError::JwtError(err)
    }
}