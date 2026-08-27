//! Contract/frontend API-version compatibility policy.

/// The supported frontend-to-contract API version pairs.
///
/// Keep this list explicit: an unknown version must not be treated as
/// compatible by accident.
pub const COMPATIBILITY_MATRIX: &[(&str, &str)] = &[("1", "2")];

#[derive(Debug, PartialEq, Eq)]
pub enum Compatibility {
    Compatible,
    Incompatible,
    UnknownFrontend,
}

pub fn check(frontend_version: &str, contract_version: &str) -> Compatibility {
    if !COMPATIBILITY_MATRIX
        .iter()
        .any(|(frontend, _)| *frontend == frontend_version)
    {
        return Compatibility::UnknownFrontend;
    }

    if COMPATIBILITY_MATRIX
        .iter()
        .any(|(frontend, contract)| {
            *frontend == frontend_version && *contract == contract_version
        })
    {
        Compatibility::Compatible
    } else {
        Compatibility::Incompatible
    }
}

#[cfg(test)]
mod tests {
    use super::{check, Compatibility};

    #[test]
    fn accepts_supported_pair() {
        assert_eq!(check("1", "2"), Compatibility::Compatible);
    }

    #[test]
    fn rejects_wrong_contract_version() {
        assert_eq!(check("1", "1"), Compatibility::Incompatible);
    }

    #[test]
    fn rejects_unknown_frontend_version() {
        assert_eq!(check("99", "2"), Compatibility::UnknownFrontend);
    }
}