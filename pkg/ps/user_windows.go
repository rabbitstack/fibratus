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
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/windows"
)

const (
	// userCacheTTL is the time to live of the successfully resolved accounts.
	// Accounts can be renamed, so we don't want to cache them forever.
	userCacheTTL = time.Minute * 45
	// userResolutionCacheSize is the maximum number of entries kept in the cache.
	userResolutionCacheSize = 128
)

var (
	users     *UserResolver
	usersOnce sync.Once
)

// Users returns the process-wide user resolver. It is shared by the
// snapshotter and the decoders, so a SID is resolved at most once.
func Users() *UserResolver {
	usersOnce.Do(func() { users = NewUserResolver() })
	return users
}

// UserResolver converts security identifiers to their associated account names.
// The OS account lookup is expensive, since it may involve RPC calls to the
// local security authority or domain controllers, and the same handful of SIDs
// repeat for virtually all processes. The resolver memoizes the results, and
// it is safe for concurrent use.
type UserResolver struct {
	usersCache *expirable.LRU[string, string]
}

// NewUserResolver creates a new user resolver.
func NewUserResolver() *UserResolver {
	return &UserResolver{
		usersCache: expirable.NewLRU[string, string](userResolutionCacheSize, nil, userCacheTTL),
	}
}

// GetUser returns the domain\\user for the given SID in string format. Empty
// strings are returned if the SID is empty or can't be resolved. Both successful
// and failed lookups are cached.
func (r *UserResolver) GetUser(ownerSidString string) string {
	sid, err := windows.StringToSid(ownerSidString)
	if err != nil {
		r.usersCache.Add(ownerSidString, "")
		return ""
	}

	user, domain, _, err := sid.LookupAccount("")
	if err != nil {
		r.usersCache.Add(ownerSidString, "")
		return ""
	}
	r.usersCache.Add(ownerSidString, domain+"\\"+user)

	return domain + "\\" + user
}

// Len returns the number of entries in the cache.
func (r *UserResolver) Len() int {
	return r.usersCache.Len()
}

func splitDomainUser(s string) (string, string) {
	if parts := strings.Split(s, `\`); len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}
