/*
 * Copyright 2026 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package policy

// ID is the unique identifier of the policy.
type ID string

// Type represents the type of the policy.
type Type string

// InternalType identifies the provider-specific flavour of the
// policy, such as the encoding of the source it was decoded from.
type InternalType string

const (
	// BehaviourPolicyType designates policies that carry standard
	// runtime detection rules.
	Behaviour Type = "behaviour"
	// SignaturePolicyType designates policies that carry signature
	// (YARA) rules.
	Signature Type = "signature"
)

// YAMLInternalType denotes the policies decoded from YAML files.
const YAMLInternalType InternalType = "yaml"

// Policy is a named group of rules and macros. All rules and macros
// are always bound to a policy.
type Policy struct {
	// ID is the unique policy identifier.
	ID ID
	// Name is the human-readable policy name.
	Name string
	// Version is the optional policy version.
	Version string
	// Description describes the purpose of the policy.
	Description string
	// Type is the policy type.
	Type Type
	// InternalType is the provider-specific policy flavour.
	InternalType InternalType
	// Source designates where the policy comes from. For file
	// system providers it is the rules root directory.
	Source string

	// Macros contains macros defined by this policy.
	Macros []*MacroDef
	// Rules contains rules defined by this policy.
	Rules []*RuleDef
}

// IsBehaviour determines if this is the behaviour policy.
func (p *Policy) IsBehaviour() bool { return p.Type == Behaviour }

// IsSignature determines if this is the signature policy.
func (p *Policy) IsSignature() bool { return p.Type == Signature }
