//! Validated domain types (newtypes) shared by the policy gate, the combiner and the API layer.

use std::fmt;

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ValidationError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds {max} characters")]
    TooLong { field: &'static str, max: usize },
    #[error("{field} contains invalid characters")]
    InvalidChars { field: &'static str },
    #[error("{field} must be within {min}..={max}, got {value}")]
    OutOfRange {
        field: &'static str,
        min: f64,
        max: f64,
        value: f64,
    },
    #[error("{field} has unknown value '{value}'")]
    UnknownValue { field: &'static str, value: String },
    #[error("context.time must be RFC 3339: {0}")]
    InvalidTime(String),
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@' | '+')
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | ':')
}

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident, $field:literal, $max:expr, $allowed:path) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and normalises (trims) a raw value.
            ///
            /// # Errors
            /// Returns [`ValidationError`] when the value is empty, too long or has invalid characters.
            pub fn parse(raw: &str) -> Result<Self, ValidationError> {
                let value = raw.trim();
                if value.is_empty() {
                    return Err(ValidationError::Empty { field: $field });
                }
                if value.chars().count() > $max {
                    return Err(ValidationError::TooLong { field: $field, max: $max });
                }
                if !value.chars().all($allowed) {
                    return Err(ValidationError::InvalidChars { field: $field });
                }
                Ok(Self(value.to_owned()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier!(
    /// Who is asking (e.g. an email or a directory id).
    SubjectId, "subject.id", 256, is_ident_char
);
identifier!(
    /// What is being accessed (e.g. an application id).
    ResourceId, "resource.id", 256, is_ident_char
);
identifier!(
    /// Lower-case role name such as `engineer` or `hr`.
    RoleName, "subject.properties.roles", 64, is_name_char
);
identifier!(
    /// Lower-case action name such as `read` or `write`.
    ActionName, "action.name", 64, is_name_char
);

macro_rules! bounded_f64 {
    ($(#[$meta:meta])* $name:ident, $field:literal, $min:expr, $max:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(f64);

        impl $name {
            /// # Errors
            /// Returns [`ValidationError::OutOfRange`] when the value is not finite or out of bounds.
            pub fn new(value: f64) -> Result<Self, ValidationError> {
                if value.is_finite() && ($min..=$max).contains(&value) {
                    Ok(Self(value))
                } else {
                    Err(ValidationError::OutOfRange { field: $field, min: $min, max: $max, value })
                }
            }

            #[must_use]
            pub fn value(self) -> f64 {
                self.0
            }
        }
    };
}

bounded_f64!(
    /// A probability in `0.0..=1.0`.
    Probability, "probability", 0.0, 1.0
);
bounded_f64!(
    /// Expected risk level in `0.0..=3.0` (low, medium, high, critical).
    RiskScore, "risk", 0.0, 3.0
);

/// Jev API key. `Debug` never reveals the secret.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    /// # Errors
    /// Returns [`ValidationError::Empty`] when the key is blank.
    pub fn new(raw: &str) -> Result<Self, ValidationError> {
        let value = raw.trim();
        if value.is_empty() {
            return Err(ValidationError::Empty {
                field: "API_KEY_JEV",
            });
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(****)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Suspended,
    Disabled,
}

impl AccountStatus {
    /// # Errors
    /// Returns [`ValidationError::UnknownValue`] for anything but `active`, `suspended` or `disabled`.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "disabled" => Ok(Self::Disabled),
            other => Err(ValidationError::UnknownValue {
                field: "subject.properties.account_status",
                value: other.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrust {
    Managed,
    Byod,
    Unknown,
    Compromised,
}

impl DeviceTrust {
    pub const ALL: [Self; 4] = [Self::Managed, Self::Byod, Self::Unknown, Self::Compromised];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Byod => "byod",
            Self::Unknown => "unknown",
            Self::Compromised => "compromised",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == name)
    }
}

/// Decision outcome. Ordered by severity so the strictest effect wins with `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    StepUp,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_trimmed_and_validated() {
        assert_eq!(
            SubjectId::parse("  alice@example.com ").unwrap().as_str(),
            "alice@example.com"
        );
        assert_eq!(
            SubjectId::parse("  "),
            Err(ValidationError::Empty {
                field: "subject.id"
            })
        );
        assert!(matches!(
            SubjectId::parse(&"a".repeat(257)),
            Err(ValidationError::TooLong { .. })
        ));
        assert!(matches!(
            ResourceId::parse("pay roll"),
            Err(ValidationError::InvalidChars { .. })
        ));
        assert!(matches!(
            RoleName::parse("Admin"),
            Err(ValidationError::InvalidChars { .. })
        ));
        assert_eq!(ActionName::parse("read").unwrap().to_string(), "read");
    }

    #[test]
    fn bounded_numbers_reject_out_of_range_and_nan() {
        assert!(Probability::new(0.0).is_ok());
        assert!(Probability::new(1.0).is_ok());
        assert!(Probability::new(1.01).is_err());
        assert!(Probability::new(f64::NAN).is_err());
        assert!((RiskScore::new(2.5).unwrap().value() - 2.5).abs() < f64::EPSILON);
        assert!(RiskScore::new(-0.1).is_err());
    }

    #[test]
    fn api_key_is_masked_in_debug() {
        let key = ApiKey::new("secret-value").unwrap();
        assert_eq!(format!("{key:?}"), "ApiKey(****)");
        assert_eq!(key.expose(), "secret-value");
        assert!(ApiKey::new(" ").is_err());
    }

    #[test]
    fn enums_parse_and_order() {
        assert_eq!(
            AccountStatus::parse("Active").unwrap(),
            AccountStatus::Active
        );
        assert_eq!(
            AccountStatus::parse("suspended").unwrap(),
            AccountStatus::Suspended
        );
        assert_eq!(
            AccountStatus::parse("disabled").unwrap(),
            AccountStatus::Disabled
        );
        assert!(AccountStatus::parse("ghost").is_err());
        assert_eq!(DeviceTrust::from_name("byod"), Some(DeviceTrust::Byod));
        assert_eq!(DeviceTrust::from_name("toaster"), None);
        assert!(Outcome::Deny > Outcome::StepUp && Outcome::StepUp > Outcome::Allow);
    }
}
