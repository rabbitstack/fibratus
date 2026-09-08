package policy

type PolicyID string

// PolicyType represents policy type
type PolicyType string

type PolicyInternalType string

const (
	// DefaultPolicyType is the default policy type
	BehaviourPolicyType PolicyType = "behaviour"
	// CustomPolicyType is the custom policy type
	SignaturePolicyType PolicyType = "signature"
)

type Policy struct {
	ID           PolicyID
	Name         string
	Version      string
	Description  string
	Type         PolicyType
	InternalType PolicyInternalType

	Macros []*MacroDef
	Rules  []*RuleDef
}
