//! `$VAR` expansion for config values (header values, a shared secret) that
//! should not sit in plaintext in a config file.

/// Replaces each `$VAR` run of word characters in `value` with that
/// environment variable. `$` not followed by a name passes through
/// unchanged. `what` names `value` in the error, e.g. an upstream's name.
pub fn expand_env(what: &str, value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }
        let mut var = String::new();
        while let Some(&next) = chars.peek() {
            if next.is_ascii_alphanumeric() || next == '_' {
                var.push(next);
                chars.next();
            } else {
                break;
            }
        }
        if var.is_empty() {
            out.push('$');
            continue;
        }
        let expanded = std::env::var(&var).map_err(|_| format!("{what}: ${var} is not set"))?;
        out.push_str(&expanded);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::expand_env;

    #[test]
    fn a_var_is_replaced_and_a_lone_dollar_is_kept() {
        unsafe { std::env::set_var("EXPAND_ENV_TEST_VAR", "secret") };
        assert_eq!(expand_env("x", "Bearer $EXPAND_ENV_TEST_VAR").unwrap(), "Bearer secret");
        assert_eq!(expand_env("x", "literally $ this").unwrap(), "literally $ this");
        assert!(expand_env("x", "$EXPAND_ENV_TEST_VAR_UNSET").is_err());
    }
}
