//! Risk scoring, ported from the semantics of `risk_scoring.py`.
//!
//! Score = sum over factors of (weight * magnitude), clamped to [0.0, 1.0].
//! Levels: score < 0.35 -> Low; < 0.65 -> Medium; otherwise High.

/// A single weighted risk factor (e.g. "irreversibility", "blast_radius").
#[derive(Debug, Clone, PartialEq)]
pub struct Factor {
    pub name: String,
    /// Relative importance, expected in [0.0, 1.0].
    pub weight: f64,
    /// Observed magnitude of the factor for this action, expected in [0.0, 1.0].
    pub magnitude: f64,
}

impl Factor {
    pub fn new(name: impl Into<String>, weight: f64, magnitude: f64) -> Self {
        Self { name: name.into(), weight, magnitude }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl RiskLevel {
    /// True when an action at this level must not be auto-approved.
    pub fn requires_approval(&self) -> bool {
        matches!(self, RiskLevel::Medium | RiskLevel::High)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RiskAssessment {
    pub score: f64,
    pub level: RiskLevel,
    /// Names of factors that contributed above `FACTOR_NOISE_FLOOR` to the score.
    pub drivers: Vec<String>,
}

/// Factors contributing less than this share of the total are not listed as drivers.
const FACTOR_NOISE_FLOOR: f64 = 0.05;

/// Clamp a raw value into the unit interval. NaN maps to 0.0 so scoring is total.
fn clamp_unit(x: f64) -> f64 {
    if x.is_nan() {
        0.0
    } else if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

fn classify(score: f64) -> RiskLevel {
    if score < 0.35 {
        RiskLevel::Low
    } else if score < 0.65 {
        RiskLevel::Medium
    } else {
        RiskLevel::High
    }
}

/// Score a set of factors. The result is deterministic and order-independent
/// up to floating-point associativity (factors are summed in input order).
pub fn assess(factors: &[Factor]) -> RiskAssessment {
    let mut total = 0.0f64;
    let mut drivers = Vec::new();
    for f in factors {
        let contribution = clamp_unit(f.weight) * clamp_unit(f.magnitude);
        total += contribution;
        if contribution > FACTOR_NOISE_FLOOR {
            drivers.push(f.name.clone());
        }
    }
    let score = clamp_unit(total);
    RiskAssessment { score, level: classify(score), drivers }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_factors_is_low() {
        let a = assess(&[]);
        assert_eq!(a.level, RiskLevel::Low);
        assert_eq!(a.score, 0.0);
    }

    #[test]
    fn out_of_range_inputs_are_clamped() {
        let a = assess(&[Factor::new("x", 5.0, -3.0)]); // 5*-3 would be -15
        assert_eq!(a.score, 0.0);
    }

    #[test]
    fn nan_is_treated_as_zero() {
        let a = assess(&[Factor::new("ghost", f64::NAN, 1.0)]);
        assert!(!a.score.is_nan());
    }
}
