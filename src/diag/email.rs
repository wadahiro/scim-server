//! Probe-email safety: template parsing/expansion and the consumer-domain
//! blocklist.
//!
//! `--probe-email`'s only consumer is `userName`/`emails[0].value` on the
//! fixture users this tool creates (`fixtures::provision`) — see that
//! module's doc comment for why nothing else needs a fresh address.

use crate::diag::DiagError;

/// Domains rejected by [`EmailTemplate::check_domain`] unless
/// `--allow-consumer-email` is passed. Matched as an exact, lowercased
/// string against the part after `@` — no public-suffix resolution, no
/// subdomain expansion (§5.8: both would add a dependency and a source of
/// misjudgement for little benefit).
const CONSUMER_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.ru",
    "qq.com",
    "naver.com",
];

/// A validated `--probe-email` template. Always contains the literal
/// substrings `{prefix}` and `{n}` — that's what [`EmailTemplate::parse`]
/// enforces, since `rfc.filter_sw`, `rfc.pagination`, and `--cleanup-only`
/// all rediscover fixtures via `userName sw "{prefix}"`, and `userName` is
/// this template's expansion: a template without `{prefix}` in it makes
/// that rediscovery key silently come up empty.
#[derive(Debug, Clone)]
pub struct EmailTemplate {
    raw: String,
}

impl EmailTemplate {
    /// Rejects a template missing either `{prefix}` or `{n}`.
    pub fn parse(raw: &str) -> Result<Self, DiagError> {
        let has_prefix = raw.contains("{prefix}");
        let has_n = raw.contains("{n}");
        if !has_prefix || !has_n {
            let mut missing = Vec::new();
            if !has_prefix {
                missing.push("{prefix}");
            }
            if !has_n {
                missing.push("{n}");
            }
            return Err(DiagError::BadArgs(format!(
                "--probe-email {raw:?} is missing {}; recommended form: \"{{prefix}}+{{n}}@corp.example.com\"",
                missing.join(" and ")
            )));
        }
        Ok(Self {
            raw: raw.to_string(),
        })
    }

    pub fn expand(&self, prefix: &str, n: u8) -> String {
        self.raw
            .replace("{prefix}", prefix)
            .replace("{n}", &n.to_string())
    }

    /// `Ok(None)` if the domain is fine as-is. `Ok(Some(warning))` if the
    /// domain is on the blocklist but `allow` overrode the rejection — the
    /// caller should surface `warning` in the report header. `Err` if the
    /// domain is blocked and `allow` is false.
    pub fn check_domain(&self, allow: bool) -> Result<Option<String>, DiagError> {
        // The blocklist only concerns the domain, which `{n}` substitution
        // never touches (it only ever appears in the local part per the
        // recommended form) — expand with a throwaway prefix/n just to get
        // a concrete address to split on '@'.
        let sample = self.expand("x", 1);
        let domain = sample
            .rsplit('@')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();

        let blocked = CONSUMER_DOMAINS.contains(&domain.as_str());
        if !blocked {
            return Ok(None);
        }
        if allow {
            Ok(Some(format!(
                "--allow-consumer-email overrode rejection of consumer email domain {domain:?}"
            )))
        } else {
            Err(DiagError::BadArgs(format!(
                "--probe-email domain {domain:?} is a consumer email provider; \
                 this tool refuses to create accounts there by default. \
                 Pass --allow-consumer-email to override (not recommended: \
                 the target may send real invitation/notification email)."
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_n() {
        let err = EmailTemplate::parse("{prefix}@example.test").unwrap_err();
        assert!(err.to_string().contains("{n}"), "{err}");
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = EmailTemplate::parse("probe+{n}@example.test").unwrap_err();
        assert!(err.to_string().contains("{prefix}"), "{err}");
    }

    #[test]
    fn rejects_missing_both() {
        let err = EmailTemplate::parse("static@example.test").unwrap_err();
        assert!(err.to_string().contains("{prefix}"), "{err}");
        assert!(err.to_string().contains("{n}"), "{err}");
    }

    #[test]
    fn expands_prefix_and_n() {
        let t = EmailTemplate::parse("{prefix}+{n}@example.test").unwrap();
        assert_eq!(
            t.expand("scimdiag-abcd1234", 1),
            "scimdiag-abcd1234+1@example.test"
        );
        assert_eq!(
            t.expand("scimdiag-abcd1234", 3),
            "scimdiag-abcd1234+3@example.test"
        );
    }

    #[test]
    fn domain_check_allows_non_consumer_domain() {
        let t = EmailTemplate::parse("{prefix}+{n}@corp.example.com").unwrap();
        assert_eq!(t.check_domain(false).unwrap(), None);
    }

    #[test]
    fn domain_check_rejects_consumer_domain_by_default() {
        let t = EmailTemplate::parse("{prefix}+{n}@gmail.com").unwrap();
        assert!(t.check_domain(false).is_err());
    }

    #[test]
    fn domain_check_allows_consumer_domain_with_override_and_warns() {
        let t = EmailTemplate::parse("{prefix}+{n}@gmail.com").unwrap();
        let warning = t.check_domain(true).unwrap();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("gmail.com"));
    }

    #[test]
    fn domain_check_is_case_insensitive_and_exact_match() {
        let t = EmailTemplate::parse("{prefix}+{n}@GMAIL.COM").unwrap();
        assert!(t.check_domain(false).is_err());
        // Not a subdomain match: mail.gmail.com is not gmail.com.
        let t2 = EmailTemplate::parse("{prefix}+{n}@mail.gmail.com").unwrap();
        assert_eq!(t2.check_domain(false).unwrap(), None);
    }
}
