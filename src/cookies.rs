use cookie::Cookie;
use hyper::{Request, Body};
use hyper::header::HeaderValue;
use crate::errors::AuthProxyError;
use crate::cookies;


pub fn get_auth_cookie(req: &Request<Body>) -> Result<Cookie, AuthProxyError> {
    let cookies_header = get_cookies(req)?;
    let cookie_header_str = cookies_header.to_str()?;
    match cookies::find_from_header(cookie_header_str, "Authorization") {
        Some(cookie) => Ok(cookie),
        None => Err(AuthProxyError::NoAuthorizationCookie())
    }
}

fn find_from_header<'a>(cookie_header: &'a str, name: &'a str) -> Option<Cookie<'a>> {
    for pair in cookie_header.split(';') {
        if let Ok(cookie) = Cookie::parse(String::from(pair)) {
            if name.eq(cookie.name()) {
                return Some(cookie);
            }
        }
    }
    None
}

fn get_cookies(req: &Request<Body>) -> Result<&HeaderValue, AuthProxyError> {
    match req.headers().get("Cookie") {
        Some(header) => Ok(header),
        None => Err(AuthProxyError::NoCookiesHeader())
    }
}

#[cfg(test)]
mod test {
    use crate::cookies::find_from_header;

    #[test]
    fn find_no_cookie() {
        assert!(find_from_header("", "key").is_none())
    }

    #[test]
    fn find_cookie_one_cookie() {
        assert_eq!(find_from_header("foo=bar", "foo").unwrap().value(), "bar")
    }

    #[test]
    fn find_cookie_two_cookies() {
        assert_eq!(find_from_header("foo=bar; baz=qux", "baz").unwrap().value(), "qux")
    }
}