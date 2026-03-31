//! CEL (Common Expression Language) evaluator for MCP policy decisions.
//!
//! Evaluates user-defined CEL expressions to make allow/deny/warn decisions
//! for MCP tool invocations. Expressions are compiled once and cached for
//! repeated evaluation. Failed compilations are logged and skipped (fail-open
//! per-rule, but the overall policy remains fail-closed via the default policy).

use sanctum_types::config::{CelRuleAction, McpCelRule};

/// Error type for CEL evaluation failures.
#[derive(Debug)]
pub enum CelError {
    /// Expression failed to compile.
    CompileError(String),
    /// Expression evaluation failed at runtime.
    EvalError(String),
    /// Expression did not return a boolean value.
    NonBoolResult,
    // NOTE: No `Timeout` variant is needed because CEL is non-Turing-complete
    // (no loops or recursion), so evaluation always terminates. If expression
    // size becomes a concern, bound it at config load time instead.
}

impl std::fmt::Display for CelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompileError(msg) => write!(f, "CEL compile error: {msg}"),
            Self::EvalError(msg) => write!(f, "CEL evaluation error: {msg}"),
            Self::NonBoolResult => write!(f, "CEL expression did not return a boolean"),
        }
    }
}

/// Result of evaluating a CEL rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CelDecision {
    /// No CEL rule matched -- defer to glob-based policy.
    NoMatch,
    /// A CEL rule matched and its action is Allow.
    Allow,
    /// A CEL rule matched and its action is Deny.
    Deny,
    /// A CEL rule matched and its action is Warn.
    Warn,
}

/// Context for CEL expression evaluation.
///
/// Contains all the variables available to CEL expressions.
pub struct CelContext {
    /// The name of the MCP tool being invoked.
    pub tool_name: String,
    /// Paths referenced by the tool invocation arguments.
    pub paths: Vec<String>,
    /// Size of the tool invocation payload in bytes.
    pub payload_size: i64,
}

/// Evaluates CEL expressions against MCP tool invocation context.
///
/// Expressions are compiled once and cached for repeated evaluation.
/// Failed compilations are logged and skipped (fail-open per-rule,
/// but the overall policy is still fail-closed via the default policy).
pub struct CelEvaluator {
    /// Compiled rules: (compiled program, action, original expression for logging).
    rules: Vec<(cel::Program, CelRuleAction, String)>,
}

impl std::fmt::Debug for CelEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CelEvaluator")
            .field(
                "rules",
                &self
                    .rules
                    .iter()
                    .map(|(_, a, e)| (a, e))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl CelEvaluator {
    /// Create a new `CelEvaluator` by compiling each CEL expression.
    ///
    /// Rules that fail to compile are logged and skipped. This means
    /// a typo in one rule does not prevent other rules from taking effect.
    #[must_use]
    pub fn new(rules: &[McpCelRule]) -> Self {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            match cel::Program::compile(&rule.expression) {
                Ok(program) => {
                    compiled.push((program, rule.action, rule.expression.clone()));
                }
                Err(err) => {
                    tracing::warn!(
                        expression = rule.expression.as_str(),
                        error = %err,
                        "skipping CEL rule that failed to compile"
                    );
                }
            }
        }
        Self { rules: compiled }
    }

    /// Evaluate all compiled CEL rules against the given context.
    ///
    /// Uses first-match-wins semantics: stops at the first rule whose
    /// expression evaluates to `true` and returns the corresponding
    /// `CelDecision`. If no rule matches, returns `CelDecision::NoMatch`.
    pub fn evaluate(&self, ctx: &CelContext) -> CelDecision {
        let mut cel_ctx = cel::Context::default();

        // Add tool_name as a string variable.
        cel_ctx.add_variable_from_value("tool_name", ctx.tool_name.clone());

        // Add paths as a list of strings.
        let path_values: Vec<cel::Value> = ctx
            .paths
            .iter()
            .map(|p| cel::Value::from(p.as_str()))
            .collect();
        cel_ctx
            .add_variable_from_value("paths", cel::Value::List(std::sync::Arc::new(path_values)));

        // Add payload_size as an integer.
        cel_ctx.add_variable_from_value("payload_size", ctx.payload_size);

        for (program, action, expr) in &self.rules {
            match program.execute(&cel_ctx) {
                Ok(cel::Value::Bool(true)) => {
                    return match action {
                        CelRuleAction::Allow => CelDecision::Allow,
                        CelRuleAction::Deny => CelDecision::Deny,
                        CelRuleAction::Warn => CelDecision::Warn,
                    };
                }
                Ok(cel::Value::Bool(false)) => {
                    // Rule did not match; continue to next rule.
                }
                Ok(_non_bool) => {
                    tracing::warn!(
                        expression = expr.as_str(),
                        "CEL expression returned non-boolean result, skipping rule"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        expression = expr.as_str(),
                        error = %err,
                        "CEL expression evaluation failed, skipping rule"
                    );
                }
            }
        }
        CelDecision::NoMatch
    }

    /// Returns `true` if no rules compiled successfully.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanctum_types::config::{CelRuleAction, McpCelRule};

    /// Helper to build a single `McpCelRule`.
    fn rule(expression: &str, action: CelRuleAction) -> McpCelRule {
        McpCelRule {
            expression: expression.to_string(),
            action,
        }
    }

    /// Helper to build a `CelContext` with sensible defaults.
    fn ctx(tool_name: &str, paths: &[&str], payload_size: i64) -> CelContext {
        CelContext {
            tool_name: tool_name.to_string(),
            paths: paths.iter().map(|s| (*s).to_string()).collect(),
            payload_size,
        }
    }

    #[test]
    fn test_empty_rules_returns_no_match() {
        let evaluator = CelEvaluator::new(&[]);
        let decision = evaluator.evaluate(&ctx("any_tool", &[], 0));
        assert_eq!(decision, CelDecision::NoMatch);
    }

    #[test]
    fn test_simple_tool_name_match() {
        let evaluator =
            CelEvaluator::new(&[rule("tool_name == \"write_file\"", CelRuleAction::Deny)]);
        let decision = evaluator.evaluate(&ctx("write_file", &[], 0));
        assert_eq!(decision, CelDecision::Deny);
    }

    #[test]
    fn test_simple_tool_name_no_match() {
        let evaluator =
            CelEvaluator::new(&[rule("tool_name == \"write_file\"", CelRuleAction::Deny)]);
        let decision = evaluator.evaluate(&ctx("read_file", &[], 0));
        assert_eq!(decision, CelDecision::NoMatch);
    }

    #[test]
    fn test_starts_with_match() {
        let evaluator = CelEvaluator::new(&[rule(
            "tool_name.startsWith(\"database_\")",
            CelRuleAction::Warn,
        )]);
        let decision = evaluator.evaluate(&ctx("database_query", &[], 0));
        assert_eq!(decision, CelDecision::Warn);
    }

    #[test]
    fn test_payload_size_check() {
        let evaluator = CelEvaluator::new(&[rule("payload_size > 10240", CelRuleAction::Deny)]);
        let decision = evaluator.evaluate(&ctx("any_tool", &[], 20000));
        assert_eq!(decision, CelDecision::Deny);
    }

    #[test]
    fn test_payload_size_below_threshold() {
        let evaluator = CelEvaluator::new(&[rule("payload_size > 10240", CelRuleAction::Deny)]);
        let decision = evaluator.evaluate(&ctx("any_tool", &[], 5000));
        assert_eq!(decision, CelDecision::NoMatch);
    }

    #[test]
    fn test_multiple_rules_first_match_wins() {
        let evaluator = CelEvaluator::new(&[
            rule("tool_name == \"write_file\"", CelRuleAction::Allow),
            rule("tool_name == \"write_file\"", CelRuleAction::Deny),
        ]);
        let decision = evaluator.evaluate(&ctx("write_file", &[], 0));
        // First rule matches with Allow, so second rule is never reached.
        assert_eq!(decision, CelDecision::Allow);
    }

    #[test]
    fn test_deny_action_maps_correctly() {
        let evaluator = CelEvaluator::new(&[rule("true", CelRuleAction::Deny)]);
        let decision = evaluator.evaluate(&ctx("any", &[], 0));
        assert_eq!(decision, CelDecision::Deny);
    }

    #[test]
    fn test_allow_action_maps_correctly() {
        let evaluator = CelEvaluator::new(&[rule("true", CelRuleAction::Allow)]);
        let decision = evaluator.evaluate(&ctx("any", &[], 0));
        assert_eq!(decision, CelDecision::Allow);
    }

    #[test]
    fn test_warn_action_maps_correctly() {
        let evaluator = CelEvaluator::new(&[rule("true", CelRuleAction::Warn)]);
        let decision = evaluator.evaluate(&ctx("any", &[], 0));
        assert_eq!(decision, CelDecision::Warn);
    }

    #[test]
    fn test_invalid_expression_skipped() {
        let evaluator =
            CelEvaluator::new(&[rule("this is not valid &&& CEL !!!", CelRuleAction::Deny)]);
        let decision = evaluator.evaluate(&ctx("any", &[], 0));
        assert_eq!(decision, CelDecision::NoMatch);
    }

    #[test]
    fn test_non_bool_expression_skipped() {
        // Expression returns an integer, not a boolean.
        let evaluator = CelEvaluator::new(&[rule("1 + 2", CelRuleAction::Deny)]);
        let decision = evaluator.evaluate(&ctx("any", &[], 0));
        assert_eq!(decision, CelDecision::NoMatch);
    }

    #[test]
    fn test_is_empty_with_no_rules() {
        let evaluator = CelEvaluator::new(&[]);
        assert!(evaluator.is_empty());
    }

    #[test]
    fn test_is_empty_with_valid_rules() {
        let evaluator = CelEvaluator::new(&[rule("true", CelRuleAction::Deny)]);
        assert!(!evaluator.is_empty());
    }

    #[test]
    fn test_is_empty_with_only_invalid_rules() {
        let evaluator = CelEvaluator::new(&[
            rule("not valid !!!", CelRuleAction::Deny),
            rule("also &&& broken", CelRuleAction::Allow),
        ]);
        assert!(evaluator.is_empty());
    }
}
