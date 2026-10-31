//! Deterministic policy definitions loaded from YAML.

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use super::domain::{ActionName, ResourceId, RoleName, ValidationError};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse policy YAML: {0}")]
    Yaml(#[from] serde_saphyr::Error),
    #[error("invalid policy: {0}")]
    Invalid(String),
}

impl From<ValidationError> for PolicyError {
    fn from(e: ValidationError) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// Allowed local hours, `start` inclusive and `end` exclusive (0..=24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Hours {
    pub start: u32,
    pub end: u32,
}

impl Hours {
    #[must_use]
    pub fn contains(self, hour: u32) -> bool {
        (self.start..self.end).contains(&hour)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    /// Expected risk score (0..=3) at or above which MFA is required.
    pub step_up_risk: f64,
    /// Expected risk score (0..=3) at or above which access is denied.
    pub deny_risk: f64,
    /// Probability of an implausible location at or above which MFA is required.
    pub step_up_location: f64,
    /// Probability of an unusual login time at or above which MFA is required.
    pub step_up_time: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            step_up_risk: 1.0,
            deny_risk: 2.0,
            step_up_location: 0.6,
            step_up_time: 0.7,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyRule {
    pub resource: ResourceId,
    pub actions: Vec<ActionName>,
    pub roles: Vec<RoleName>,
    pub hours: Option<Hours>,
    pub require_managed_device: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicySet {
    pub thresholds: Thresholds,
    pub rules: Vec<PolicyRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    thresholds: Thresholds,
    policies: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    resource: String,
    actions: Vec<String>,
    roles: Vec<String>,
    #[serde(default)]
    hours: Option<Hours>,
    #[serde(default)]
    require_managed_device: bool,
}

impl PolicySet {
    /// # Errors
    /// Returns [`PolicyError`] when the YAML is malformed or contains invalid values.
    pub fn from_yaml(text: &str) -> Result<Self, PolicyError> {
        let raw: RawFile = serde_saphyr::from_str(text)?;
        let t = raw.thresholds;
        let probabilities_ok = [t.step_up_location, t.step_up_time]
            .iter()
            .all(|p| (0.0..=1.0).contains(p));
        if !probabilities_ok
            || !(0.0..=3.0).contains(&t.step_up_risk)
            || t.step_up_risk > t.deny_risk
        {
            return Err(PolicyError::Invalid(format!(
                "inconsistent thresholds: {t:?}"
            )));
        }

        let mut rules = Vec::with_capacity(raw.policies.len());
        for r in raw.policies {
            if let Some(h) = r.hours
                && (h.start >= h.end || h.end > 24)
            {
                return Err(PolicyError::Invalid(format!(
                    "hours for '{}' must satisfy start < end <= 24",
                    r.resource
                )));
            }
            let resource = ResourceId::parse(&r.resource)?;
            if rules.iter().any(|x: &PolicyRule| x.resource == resource) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate resource '{resource}'"
                )));
            }
            rules.push(PolicyRule {
                resource,
                actions: r
                    .actions
                    .iter()
                    .map(|a| ActionName::parse(a))
                    .collect::<Result<_, _>>()?,
                roles: r
                    .roles
                    .iter()
                    .map(|x| RoleName::parse(x))
                    .collect::<Result<_, _>>()?,
                hours: r.hours,
                require_managed_device: r.require_managed_device,
            });
        }
        Ok(Self {
            thresholds: t,
            rules,
        })
    }

    /// # Errors
    /// Returns [`PolicyError`] when the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        Self::from_yaml(&std::fs::read_to_string(path)?)
    }

    #[must_use]
    pub fn find(&self, resource: &ResourceId) -> Option<&PolicyRule> {
        self.rules.iter().find(|r| &r.resource == resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r"
thresholds:
  step_up_risk: 1.2
policies:
  - resource: payroll
    actions: [read, write]
    roles: [hr, admin]
    hours: { start: 7, end: 22 }
    require_managed_device: true
  - resource: wiki
    actions: [read]
    roles: [engineer]
";

    #[test]
    fn parses_rules_and_merges_default_thresholds() {
        let set = PolicySet::from_yaml(SAMPLE).unwrap();
        assert!((set.thresholds.step_up_risk - 1.2).abs() < f64::EPSILON);
        assert!((set.thresholds.deny_risk - 2.0).abs() < f64::EPSILON);
        let payroll = set.find(&ResourceId::parse("payroll").unwrap()).unwrap();
        assert!(payroll.require_managed_device);
        assert!(payroll.hours.unwrap().contains(7));
        assert!(!payroll.hours.unwrap().contains(22));
        assert!(set.find(&ResourceId::parse("nope").unwrap()).is_none());
    }

    #[test]
    fn rejects_invalid_policies() {
        let bad_hours =
            "policies:\n  - {resource: a, actions: [read], roles: [x], hours: {start: 9, end: 9}}";
        assert!(matches!(
            PolicySet::from_yaml(bad_hours),
            Err(PolicyError::Invalid(_))
        ));
        let dup = "policies:\n  - {resource: a, actions: [read], roles: [x]}\n  - {resource: a, actions: [read], roles: [x]}";
        assert!(matches!(
            PolicySet::from_yaml(dup),
            Err(PolicyError::Invalid(_))
        ));
        let bad_role = "policies:\n  - {resource: a, actions: [read], roles: [Admin]}";
        assert!(matches!(
            PolicySet::from_yaml(bad_role),
            Err(PolicyError::Invalid(_))
        ));
        let bad_thr = "thresholds: {step_up_risk: 2.5, deny_risk: 2.0}\npolicies: []";
        assert!(matches!(
            PolicySet::from_yaml(bad_thr),
            Err(PolicyError::Invalid(_))
        ));
        assert!(matches!(
            PolicySet::from_yaml("policies: 3"),
            Err(PolicyError::Yaml(_))
        ));
        assert!(matches!(
            PolicySet::load(Path::new("does/not/exist.yaml")),
            Err(PolicyError::Io(_))
        ));
    }

    #[test]
    fn bundled_policy_file_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.yaml");
        assert!(!PolicySet::load(&path).unwrap().rules.is_empty());
    }
}
