package policy

// RuleFilter decides if the rule is accepted. Rejected rules are
// dropped by the loader.
type RuleFilter func(*RuleDef) bool

// MacroFilter decides if the macro is accepted. Rejected macros
// are dropped by the loader.
type MacroFilter func(*MacroDef) bool

// EnabledRuleFilter accepts rules that are not explicitly disabled.
func EnabledRuleFilter(r *RuleDef) bool { return !r.IsDisabled() }
