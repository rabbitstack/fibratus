//go:build integration

/*
 * Copyright 2019-present by Nedim Sabic Sabic
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

package ps

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestResolver() *UserResolver {
	return NewUserResolver()
}

func TestUserResolverCachesSuccessfulLookups(t *testing.T) {
	r := newTestResolver()

	for range 5 {
		domain, username := splitDomainUser(r.GetUser("S-1-5-18"))
		assert.Equal(t, "NT AUTHORITY", domain)
		assert.Equal(t, "SYSTEM", username)
	}

	assert.Equal(t, 1, r.Len())
}

func TestUserResolverDistinguishesSIDs(t *testing.T) {
	r := newTestResolver()

	_, username := splitDomainUser(r.GetUser("S-1-5-18"))
	assert.Equal(t, "SYSTEM", username)
	_, username = splitDomainUser(r.GetUser("S-1-5-19"))
	assert.Equal(t, "LOCAL SERVICE", username)
	assert.Equal(t, 2, r.Len())
}

func TestUserResolverEmptySID(t *testing.T) {
	r := newTestResolver()

	domain, username := splitDomainUser(r.GetUser(""))
	assert.Empty(t, domain)
	assert.Empty(t, username)
	assert.Equal(t, 1, r.Len())
}
