//! Removal of `debugger` statements from the scripts the proxy serves.

/// Drops every whole-word `debugger` occurrence that is actually a statement
/// (not a property name someone happened to call `debugger`, see
/// `remove_debugger_statements`), leaving whatever follows it (`;`, a line
/// break, `}`) in place so the statement it sat in becomes an empty one
/// instead of a syntax error.
///
/// A body that is not valid UTF-8 is returned unchanged.
pub(super) fn strip_debugger(body: Vec<u8>) -> Vec<u8> {
    match String::from_utf8(body) {
        Ok(text) => remove_debugger_statements(&text).into_bytes(),
        Err(err) => err.into_bytes(),
    }
}

const KEYWORD: &str = "debugger";

fn remove_debugger_statements(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(found) = text[from..].find(KEYWORD) {
        let start = from + found;
        let end = start + KEYWORD.len();
        out.push_str(&text[from..start]);
        // Not a statement, but a property name instead, right before a `:`
        // (an object key) or `(` (a method's own name), or right after a `.`
        // (plain or optional-chained, `?.`) -- `debugger` is a reserved
        // word, but still a valid property name in any of those positions,
        // so dropping it there corrupts the syntax instead of just erasing a
        // no-op statement.
        let is_statement = (start == 0 || (!is_word_byte(bytes[start - 1]) && bytes[start - 1] != b'.'))
            && (end >= bytes.len() || (!is_word_byte(bytes[end]) && bytes[end] != b':' && bytes[end] != b'('));
        if !is_statement {
            out.push_str(KEYWORD);
        }
        from = end;
    }
    out.push_str(&text[from..]);
    out
}

/// Whether `b` can be part of a JS identifier, so e.g. `debuggerTool` is left
/// untouched.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_a_minified_debugger_statement() {
        let out = String::from_utf8(strip_debugger(b"a();debugger;b();".to_vec())).unwrap();
        assert_eq!(out, "a();;b();");
    }

    #[test]
    fn strips_debugger_terminated_by_a_line_break() {
        let out = String::from_utf8(strip_debugger(b"a();\ndebugger\nb();".to_vec())).unwrap();
        assert_eq!(out, "a();\n\nb();");
    }

    #[test]
    fn strips_debugger_right_before_a_closing_brace() {
        let out = String::from_utf8(strip_debugger(b"if(x){debugger}".to_vec())).unwrap();
        assert_eq!(out, "if(x){}");
    }

    #[test]
    fn leaves_identifiers_that_merely_contain_the_word_alone() {
        let body = b"let debuggerTool = 1; useDebugger(); const x = isDebugger;".to_vec();
        assert_eq!(strip_debugger(body.clone()), body);
    }

    #[test]
    fn leaves_a_debugger_property_access_alone() {
        // Seen in the wild (TikTok's bundled SDKs): stripping the word here
        // left `obj. = x;`, a syntax error -- `debugger` as a property name
        // is always valid, statement or not.
        let body = b"obj.debugger = x; a.b.debugger(); c?.debugger;".to_vec();
        assert_eq!(strip_debugger(body.clone()), body);
    }

    #[test]
    fn leaves_a_debugger_object_key_or_method_name_alone() {
        let body = b"({ debugger: true, debugger() {} });".to_vec();
        assert_eq!(strip_debugger(body.clone()), body);
    }

    #[test]
    fn a_body_that_is_not_utf8_is_left_alone() {
        let body = vec![0xff, 0xfe, b'd', b'e', b'b', b'u', b'g'];
        assert_eq!(strip_debugger(body.clone()), body);
    }
}
