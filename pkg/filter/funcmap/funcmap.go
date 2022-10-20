/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package funcmap

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	log "github.com/sirupsen/logrus"
	"sort"

	"strings"
)

func printEvt(kevts ...*kevent.Kevent) string {
	if len(kevts) == 1 {
		b, err := kevts[0].RenderDefaultTemplate()
		if err != nil {
			log.Warnf("failed to render event template: %v", err)
			return ""
		}
		return string(b)
	}
	var sb strings.Builder
	for i, kevt := range kevts {
		sb.WriteString(fmt.Sprintf("Event #%d\n\n", i+1))
		b, err := kevt.RenderDefaultTemplate()
		if err != nil {
			log.Warnf("failed to render event template: %v", err)
			continue
		}
		sb.WriteString(string(b))
		sb.WriteRune('\n')
	}
	return sb.String()
}

func printEvts(kevts map[string]*kevent.Kevent) string {
	evts := make([]*kevent.Kevent, 0, len(kevts))
	for _, kevt := range kevts {
		evts = append(evts, kevt)
	}
	sort.Slice(evts, func(i, j int) bool { return evts[i].Timestamp.Unix() < evts[j].Timestamp.Unix() })
	return printEvt(evts...)
}
