//! Rule-based selection of the scripts injected into HTML pages and worker
//! scripts (see `Config::inject_scripts`/`Config::worker_inject_scripts`).

use super::blocklist;

/// A script injected into the HTML pages or Worker scripts whose address
/// matches `host` and `path_prefix`. More than one rule may match the same
/// target -- see [`matching`].
pub struct InjectRule {
    /// The host this rule applies to, and its subdomains (see
    /// [`blocklist::is_host_or_subdomain`]). Empty matches every host.
    pub host: &'static str,
    /// Only paths starting with this are matched. Empty matches every path.
    pub path_prefix: &'static str,
    /// The script itself.
    pub script: &'static str,
}

/// The scripts of `rules` whose `host`/`path_prefix` matches `host`/`path`,
/// in the order they're listed -- so more than one rule can apply to the same
/// target, e.g. a wide host-only rule plus a narrower path-specific one, and
/// both end up injected into it.
pub(super) fn matching<'a>(rules: &'a [InjectRule], host: &str, path: &str) -> impl Iterator<Item = &'a str> {
    rules.iter().filter(move |rule| matches(rule, host, path)).map(|rule| rule.script)
}

fn matches(rule: &InjectRule, host: &str, path: &str) -> bool {
    (rule.host.is_empty() || blocklist::is_host_or_subdomain(host, rule.host)) && path.starts_with(rule.path_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_host_and_path_prefix() {
        let rules = [
            InjectRule { host: "tiktok.com", path_prefix: "", script: "a" },
            InjectRule { host: "tiktok.com", path_prefix: "/foo", script: "b" },
            InjectRule { host: "other.com", path_prefix: "", script: "c" },
        ];
        let got: Vec<_> = matching(&rules, "tiktok.com", "/foo/bar").collect();
        assert_eq!(got, vec!["a", "b"]);
    }

    #[test]
    fn an_empty_host_matches_every_host() {
        let rules = [InjectRule { host: "", path_prefix: "", script: "everywhere" }];
        let got: Vec<_> = matching(&rules, "anything.example", "/").collect();
        assert_eq!(got, vec!["everywhere"]);
    }

    #[test]
    fn an_empty_path_prefix_matches_every_path() {
        let rules = [InjectRule { host: "tiktok.com", path_prefix: "", script: "a" }];
        let got: Vec<_> = matching(&rules, "tiktok.com", "/any/path").collect();
        assert_eq!(got, vec!["a"]);
    }

    #[test]
    fn a_host_rule_also_matches_its_subdomains_only() {
        let rules = [InjectRule { host: "tiktok.com", path_prefix: "", script: "a" }];
        assert_eq!(matching(&rules, "www.tiktok.com", "/").collect::<Vec<_>>(), vec!["a"]);
        assert!(matching(&rules, "nottiktok.com", "/").next().is_none());
    }

    #[test]
    fn several_rules_can_match_the_same_target_and_all_apply() {
        let rules = [
            InjectRule { host: "", path_prefix: "", script: "base" },
            InjectRule { host: "tiktok.com", path_prefix: "", script: "extra" },
            InjectRule { host: "mapgenie.io", path_prefix: "", script: "unrelated" },
        ];
        let got: Vec<_> = matching(&rules, "tiktok.com", "/").collect();
        assert_eq!(got, vec!["base", "extra"]);
    }
}
