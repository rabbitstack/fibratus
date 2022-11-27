/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package processors

import (
	"expvar"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/yara"
	log "github.com/sirupsen/logrus"
)

// imageYaraScans stores the total count of yara image scans
var imageYaraScans = expvar.NewInt("yara.image.scans")

type imageProcessor struct {
	snap ps.Snapshotter
	yara yara.Scanner
}

func newImageProcessor(snap ps.Snapshotter, yara yara.Scanner) Processor {
	return &imageProcessor{snap: snap, yara: yara}
}

func (imageProcessor) Name() ProcessorType { return Image }

func (i *imageProcessor) ProcessEvent(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if i.yara != nil && kevt.Type == ktypes.LoadImage {
		filename := kevt.GetParamAsString(kparams.ImageFilename)
		// scan the target filename
		go func() {
			imageYaraScans.Add(1)
			err := i.yara.ScanFile(filename, kevt)
			if err != nil {
				log.Warnf("unable to run yara scanner on %s image: %v", filename, err)
			}
		}()
	}
	if kevt.IsUnloadImage() {
		return kevt, false, i.snap.Remove(kevt)
	}
	return kevt, false, i.snap.Write(kevt)
}

func (imageProcessor) Close() {}
