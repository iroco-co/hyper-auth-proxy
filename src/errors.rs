use base64::DecodeError;
use jwt::Error as JwtError;
use hyper::header::ToStrError;

#[derive(Debug)]
pub enum AuthProxyError {
    DecodeError(DecodeError),
    JwtError(JwtError),
    NoCookiesHeader(),
    NoAuthorizationCookie(),
    StrError(ToStrError)
}

impl std::fmt::Display for AuthProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthProxyError::DecodeError(de) => write!(f, "cannot decode base64 ({})", de),
            AuthProxyError::JwtError(jwte) => write!(f, "cannot decode jwt token ({})", jwte),
            AuthProxyError::NoCookiesHeader() => write!(f, "no cookies header"),
            AuthProxyError::NoAuthorizationCookie() => write!(f, "no auth cookie"),
            AuthProxyError::StrError(str_err) => write!(f, "string error ({})", str_err)
        }
    }
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