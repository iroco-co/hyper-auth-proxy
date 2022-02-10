use cookie::Cookie;

pub(crate) fn find_from_header<'a>(cookie_header: &'a str, name: &'a str) -> Option<Cookie<'a>> {
    for pair in cookie_header.split(';') {
        if let Ok(cookie) = Cookie::parse(String::from(pair)) {
            if name.eq(cookie.name()) {
                return Some(cookie);
            }
        }
    }
    None
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