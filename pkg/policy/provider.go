/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

// Provider supplies policies to the rule engine. Providers are pluggable.
// Rules currently come from YAML files in local directories (DirProvider),
// but other providers, such as a gRPC service that streams the policies to
// bidirectional channels, can implement the same contract.
type Provider interface {
	// Type returns the provider type used in logs and error messages.
	Type() string

	// LoadPolicies reads all policies from the provider. Providers should return
	// the policies that could be successfully decoded along with an error
	// that describes the failures, so callers can decide how to proceed.
	LoadPolicies() ([]*Policy, error)

	// SetOnPoliciesChanged registers the callback the provider invokes
	// when the policies it serves have changed. The callback must be
	// registered before Start is called.
	SetOnPoliciesChanged(cb func())

	// Start starts the provider background work, such as watching for
	// changes in policy sources.
	Start() error

	// Close releases the provider's resources and stops all background work.
	Close() error
}
