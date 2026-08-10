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

package event

type queuePlatform struct {
	decorator *StackwalkDecorator
}

func (q *Queue) initPlatform() {
	q.decorator = NewStackwalkDecorator(q)
}

func (q *Queue) closePlatform() {
	q.decorator.Stop()
}

func (q *Queue) pushPlatform(e *Event) (bool, error) {
	if q.stackEnrichment {
		if e.Type.CanEnrichStack() {
			q.decorator.Push(e)
			return true, nil
		}
		if e.IsStackWalk() {
			q.decorator.Pop(e)
			return true, nil
		}
	}
	if e.IsStackWalk() {
		return true, nil
	}
	return false, nil
}
