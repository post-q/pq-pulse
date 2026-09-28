const LEGAL_SUFFIXES: &[&str] = &["sa", "ltd", "inc", "llc", "gmbh"];

const BOUNDARY_NOISE: &[&str] = &["pl", "com", "net", "org", "sk", "eu", "de", "gov", "www"];

const GENERIC_WORDS: &[&str] = &[
    "group",
    "services",
    "service",
    "technology",
    "technologies",
    "network",
    "networks",
    "hosting",
    "cloud",
    "telecom",
];

const MIN_COMPACT_PREFIX: usize = 5;

const MIN_TOKEN: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub tokens: Vec<String>,
    pub compact: String,
}

pub(crate) fn normalize(text: &str) -> Option<Identity> {
    let mut tokens: Vec<String> = text
        .to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| token.chars().all(|c| c.is_ascii_alphabetic()))
        .filter(|token| token.len() >= MIN_TOKEN)
        .filter(|token| !LEGAL_SUFFIXES.contains(token))
        .filter(|token| !BOUNDARY_NOISE.contains(token))
        .filter(|token| !GENERIC_WORDS.contains(token))
        .map(String::from)
        .collect();
    tokens.sort();
    tokens.dedup();
    if tokens.is_empty() {
        return None;
    }
    let compact = tokens.concat();
    Some(Identity { tokens, compact })
}

pub(crate) fn matches_identity(a: &Identity, b: &Identity) -> bool {
    if a.compact == b.compact {
        return true;
    }
    let (small, large) = if a.tokens.len() <= b.tokens.len() {
        (&a.tokens, &b.tokens)
    } else {
        (&b.tokens, &a.tokens)
    };
    if !small.is_empty()
        && (small.len() >= 2 || small[0].len() >= 4)
        && small.iter().all(|token| large.contains(token))
    {
        return true;
    }
    let (short, long) = if a.compact.len() <= b.compact.len() {
        (&a.compact, &b.compact)
    } else {
        (&b.compact, &a.compact)
    };
    short.len() >= MIN_COMPACT_PREFIX && long.starts_with(short.as_str())
}

pub(crate) fn display_name(compact: &str) -> String {
    if compact.len() <= 3 {
        compact.to_uppercase()
    } else {
        let mut chars = compact.chars();
        match chars.next() {
            Some(first) => {
                first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
            }
            None => compact.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(text: &str) -> Identity {
        normalize(text).unwrap()
    }

    #[test]
    fn normalization_strips_suffixes_noise_and_digits() {
        assert_eq!(id("mBank"), id("MBANK-SA"));
        assert_eq!(id("MBANK-SA").compact, "mbank");
        assert_eq!(id("PL-MBANKPL").compact, "mbankpl");
        assert_eq!(id("mfinanse.sk").compact, "mfinanse");
        assert_eq!(id("war01mail1.brebank.com.pl").compact, "brebank");
        assert_eq!(normalize("AS13274 MBANK-SA").unwrap().compact, "mbank");
        assert!(normalize("13274").is_none());
        assert_eq!(normalize("www.example").unwrap().compact, "example");
    }

    #[test]
    fn pl_mbankpl_matches_mbank_through_the_prefix_rule() {
        assert!(matches_identity(&id("PL-MBANKPL"), &id("mBank")));
        assert!(matches_identity(&id("mBank"), &id("PL-MBANKPL")));
    }

    #[test]
    fn subset_matches_need_strength() {
        assert!(!matches_identity(&id("ovh"), &id("ovh-dedicated-fo")));
        assert!(matches_identity(&id("pinb"), &id("pinb-gov-warsaw")));
        assert!(matches_identity(
            &id("mbank-traf"),
            &id("mbank-traf-warsaw")
        ));
    }

    #[test]
    fn unrelated_identities_never_match() {
        assert!(!matches_identity(&id("mbank"), &id("mfaktoring")));
        assert!(!matches_identity(&id("alior"), &id("santander")));
    }

    #[test]
    fn generic_words_collapse_to_nothing() {
        assert!(normalize("Hosting Services Group").is_none());
        assert!(normalize("SA Ltd").is_none());
        assert!(normalize("cloud").is_none());
    }

    #[test]
    fn display_names_are_capitalized() {
        assert_eq!(display_name("mbank"), "Mbank");
        assert_eq!(display_name("ovh"), "OVH");
    }
}
