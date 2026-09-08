package policy

// MacroID represents the ID of a macro
type MacroID = string

type MacroDef struct {
	ID          MacroID  `yaml:"id" json:"id"`
	Expression  string   `yaml:"expression,omitempty" json:"expression,omitempty" jsonschema:"oneof_required=MacroWithExpression"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Values      []string `yaml:"values,omitempty" json:"values,omitempty" jsonschema:"oneof_required=MacroWithValues"`
}

type RuleID string

type RuleDef struct {
	ID          RuleID
	Name        string
	Version     string
	Description string
	Condition   string
	Tags        map[string]string
}
