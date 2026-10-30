//! Rewriting of the HTML documents the proxy serves.

/// Points `https://` URLs in the tags of an HTML document at `scheme`, and
/// injects `scripts`, in order. The caller's script does the same for URLs the
/// page's own scripts request at runtime.
///
/// A body that is not valid UTF-8 is returned unchanged.
pub(super) fn rewrite(body: Vec<u8>, scheme: &str, scripts: &[String]) -> Vec<u8> {
    match String::from_utf8(body) {
        Ok(html) => inject_scripts(rewrite_urls(&html, scheme), scripts).into_bytes(),
        Err(err) => err.into_bytes(),
    }
}

/// Only `src` and `href` attributes are rewritten. URLs inside inline JSON/JS
/// stay `https://`: page code often tests them with `/^https?:/` to tell
/// absolute from relative, and would glue the origin onto a `scheme://` one.
/// The injected script rewrites them when they are actually requested.
fn rewrite_urls(html: &str, scheme: &str) -> String {
    let mut html = html.to_string();
    for attr in ["src", "href"] {
        for quote in ['"', '\''] {
            html = html.replace(
                &format!("{attr}={quote}https://"),
                &format!("{attr}={quote}{scheme}://"),
            );
        }
    }
    html
}

/// Puts `scripts` first in `<head>`, each in a tag of its own so that one that
/// fails to parse does not take the others down, so they run before any page
/// script. Goes after the opening tag, since text before the doctype triggers
/// quirks mode.
fn inject_scripts(mut html: String, scripts: &[String]) -> String {
    let lower = html.to_ascii_lowercase();
    let after_open_tag = |name: &str| {
        let mut from = 0;
        while let Some(found) = lower[from..].find(name) {
            let start = from + found;
            let end = start + name.len();
            if matches!(
                lower.as_bytes().get(end),
                Some(b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/')
            ) {
                return lower[end..].find('>').map(|close| end + close + 1);
            }
            from = end;
        }
        None
    };
    let at = after_open_tag("<head")
        .or_else(|| after_open_tag("<html"))
        .unwrap_or(0);
    let tags: String = scripts
        .iter()
        .map(|script| format!("<script>{script}</script>"))
        .collect();
    html.insert_str(at, &tags);
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = "var u = 'https://x.test/';";

    fn scripts() -> Vec<String> {
        vec![SCRIPT.to_string()]
    }

    #[test]
    fn rewrites_only_src_and_href_attributes() {
        let html = concat!(
            r#"<script src="https://a.com/x.js"></script>"#,
            r#"<link rel=stylesheet href='https://b.com/s.css'>"#,
            r#"<script>var api = "https://webcast.tiktok.com"; var j = {"src":"https://c.com"};</script>"#,
        );
        let out = rewrite_urls(html, "htl");
        assert!(out.contains(r#"src="htl://a.com/x.js""#));
        assert!(out.contains("href='htl://b.com/s.css'"));
        assert!(out.contains(r#""https://webcast.tiktok.com""#));
        assert!(out.contains(r#"{"src":"https://c.com"}"#));
    }

    #[test]
    fn injects_script_first_in_head() {
        let out = inject_scripts(
            "<!DOCTYPE html><HTML><header></header><head lang=x><meta></head>".into(),
            &scripts(),
        );
        let tag = format!("<script>{SCRIPT}</script>");
        assert!(out.starts_with("<!DOCTYPE html><HTML><header></header><head lang=x>"));
        assert!(out.contains(&format!("<head lang=x>{tag}<meta>")));
    }

    #[test]
    fn injects_script_without_head() {
        let out = inject_scripts("<html><body></body></html>".into(), &scripts());
        assert!(out.starts_with(&format!("<html><script>{SCRIPT}</script>")));
    }

    #[test]
    fn rewrite_leaves_the_injected_script_untouched() {
        // The script itself mentions `https://`; the rewrite must not touch it.
        let out = String::from_utf8(rewrite(b"<head></head>".to_vec(), "htl", &scripts())).unwrap();
        assert!(out.contains(SCRIPT));
    }

    #[test]
    fn every_script_gets_its_own_tag_in_order() {
        let scripts = vec!["first();".to_string(), "second();".to_string()];
        let out = inject_scripts("<head></head>".into(), &scripts);
        assert_eq!(
            out,
            "<head><script>first();</script><script>second();</script></head>"
        );
    }

    #[test]
    fn a_body_that_is_not_utf8_is_left_alone() {
        let body = vec![0xff, 0xfe, b'<', b'h', b'e', b'a', b'd', b'>'];
        assert_eq!(rewrite(body.clone(), "htl", &scripts()), body);
    }
}
