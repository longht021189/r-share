//! Ad, tracking and telemetry endpoints that the proxy answers itself.

/// `(host, path prefix)` pairs. Found by logging the requests of a dev run; an
/// empty prefix blocks the whole host. A host also covers its subdomains (ad
/// stacks hand out hashed or per-region ones). A blocked request gets an empty
/// 204 and never reaches the network.
const BLOCKED: &[(&str, &str)] = &[
    // ByteDance analytics event collection (MCS) and Slardar monitoring.
    ("mcs-sg.tiktokv.com", ""),
    ("mon.tiktokv.com", ""),
    ("mon-sg.tiktokv.com", ""),
    // Error and performance reports: the web SDK's report endpoint, and the
    // worker's report host.
    ("mssdk-sg.tiktok.com", "/web/report"),
    ("mon-va.byteoversea.com", ""),
    // Usage uploads.
    ("www.tiktok.com", "/tiktok/v1/screen_time/upload"),
    ("www.tiktok.com", "/tiktok/v1/app_open_times/upload"),
    // Google Sign-In, wholesale: the auth flow itself, its button/library
    // assets, and the signed-in user's avatar.
    ("accounts.google.com", ""),
    ("ssl.gstatic.com", ""),
    ("googleusercontent.com", ""),
    // Ads on MapGenie (Ziff Davis): Google Ad Manager and AdSense, the header
    // bidding exchanges behind them, and ad verification.
    ("googlesyndication.com", ""),
    ("doubleclick.net", ""),
    ("adtrafficquality.google", ""),
    ("adsrvr.org", ""),
    ("amazon-adsystem.com", ""),
    ("doubleverify.com", ""),
    ("dv.tech", ""),
    ("confiant-integrations.net", ""),
    ("id5-sync.com", ""),
    ("3lift.com", ""),
    ("openx.net", ""),
    ("rubiconproject.com", ""),
    ("casalemedia.com", ""),
    ("pubmatic.com", ""),
    ("yellowblue.io", ""),
    ("openwebmp.com", ""),
    ("the-ozone-project.com", ""),
    ("criteo.com", ""),
    ("rlcdn.com", ""),
    ("bidpapers.com", ""),
    ("cdn.ziffstatic.com", "/pg/openads.js"),
    ("cdn.ziffstatic.com", "/pg/mapgenie.prebid.js"),
    // Analytics and tracking on the same pages.
    ("googletagmanager.com", ""),
    ("clarity.ms", ""),
    ("chartbeat.net", ""),
    ("chartbeat.com", ""),
    ("scorecardresearch.com", ""),
    ("zdbb.net", ""),
    ("metrics.rapidedge.io", ""),
    // Cloudflare's own Real User Monitoring beacon, injected at the edge into
    // every HTML page truyen.moe serves.
    ("truyen.moe", "/cdn-cgi/rum"),
    // Google's ad remarketing and conversion pings. Only these paths: the same
    // hosts serve reCAPTCHA. The country domain follows the user's region, so
    // this covers the ones seen (.com and .com.vn), not all of them.
    ("www.google.com", "/pagead/"),
    ("www.google.com", "/ccm/collect"),
    ("www.google.com", "/rmkt/collect/"),
    ("www.google.com.vn", "/pagead/"),
];

/// Whether a request for `path` on `host` is blocked.
pub(super) fn is_blocked(host: &str, path: &str) -> bool {
    BLOCKED
        .iter()
        .any(|(h, prefix)| is_host_or_subdomain(host, h) && path.starts_with(prefix))
}

pub(super) fn is_host_or_subdomain(host: &str, blocked: &str) -> bool {
    host == blocked
        || host
            .strip_suffix(blocked)
            .is_some_and(|rest| rest.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_by_host_and_path_prefix() {
        assert!(is_blocked("mcs-sg.tiktokv.com", "/v1/list"));
        assert!(is_blocked("mssdk-sg.tiktok.com", "/web/report"));
        assert!(!is_blocked("mssdk-sg.tiktok.com", "/web/other"));
        assert!(is_blocked("mon-va.byteoversea.com", "/anything"));
        assert!(is_blocked(
            "www.tiktok.com",
            "/tiktok/v1/screen_time/upload/"
        ));
        assert!(!is_blocked(
            "www.tiktok.com",
            "/tiktok/v1/screen_time/list/"
        ));
        assert!(!is_blocked("www.tiktok.com", "/api/recommend/item_list/"));
    }

    #[test]
    fn a_blocked_host_covers_its_subdomains_only() {
        assert!(is_blocked(
            "pagead2.googlesyndication.com",
            "/pcs/activeview"
        ));
        assert!(is_blocked("googlesyndication.com", "/"));
        assert!(!is_blocked("notgooglesyndication.com", "/"));
        assert!(!is_blocked("googlesyndication.com.example.org", "/"));
    }

    #[test]
    fn google_pings_are_blocked_but_recaptcha_is_not() {
        assert!(is_blocked("www.google.com", "/pagead/1p-user-list/1/"));
        assert!(is_blocked("www.google.com", "/ccm/collect"));
        assert!(!is_blocked("www.google.com", "/recaptcha/api2/aframe"));
    }

    #[test]
    fn google_sign_in_is_blocked_wholesale() {
        assert!(is_blocked("accounts.google.com", "/o/oauth2/auth"));
        assert!(is_blocked("ssl.gstatic.com", "/button-manifest/v1.js"));
        assert!(is_blocked("lh3.googleusercontent.com", "/a/avatar.jpg"));
        assert!(is_blocked("googleusercontent.com", "/a/avatar.jpg"));
    }

    #[test]
    fn cloudflares_rum_beacon_is_blocked_but_the_rest_of_the_site_is_not() {
        assert!(is_blocked("truyen.moe", "/cdn-cgi/rum?a=1"));
        assert!(!is_blocked("truyen.moe", "/cdn-cgi/l/chk_jschl"));
        assert!(!is_blocked("truyen.moe", "/chapter/1"));
    }

    #[test]
    fn only_the_ad_scripts_of_ziffstatic_are_blocked() {
        assert!(is_blocked("cdn.ziffstatic.com", "/pg/openads.js"));
        assert!(!is_blocked("cdn.ziffstatic.com", "/jst/zdconsent.js"));
        assert!(!is_blocked("cdn.ziffstatic.com", "/pg/mapgenie.js"));
    }
}
