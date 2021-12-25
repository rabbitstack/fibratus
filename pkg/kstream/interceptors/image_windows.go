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

package interceptors

import (
	"expvar"

	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/yara"
	log "github.com/sirupsen/logrus"
)

// imageYaraScans stores the total count of yara image scans
var imageYaraScans = expvar.NewInt("yara.image.scans")

type imageInterceptor struct {
	devMapper fs.DevMapper
	snap      ps.Snapshotter
	yara      yara.Scanner
}

func newImageInterceptor(snap ps.Snapshotter, devMapper fs.DevMapper, yara yara.Scanner) KstreamInterceptor {
	return &imageInterceptor{snap: snap, devMapper: devMapper, yara: yara}
}

func (imageInterceptor) Name() InterceptorType { return Image }

func (i *imageInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Type == ktypes.LoadImage || kevt.Type == ktypes.UnloadImage || kevt.Type == ktypes.EnumImage {
		// normalize image parameters to convert the size of hex to decimal representation
		// and replace the DOS image path to regular drive-based file path
		pid, err := kevt.Kparams.GetUint32(kparams.ProcessID)
		if err != nil {
			return kevt, true, err
		}
		if err := kevt.Kparams.Set(kparams.ProcessID, pid, kparams.PID); err != nil {
			return kevt, true, err
		}
		size, _ := kevt.Kparams.GetHexAsUint32(kparams.ImageSize)
		if err := kevt.Kparams.Set(kparams.ImageSize, size, kparams.Uint32); err != nil {
			return kevt, true, err
		}
		filename, _ := kevt.Kparams.GetString(kparams.ImageFilename)
		if err := kevt.Kparams.Set(kparams.ImageFilename, i.devMapper.Convert(filename), kparams.UnicodeString); err != nil {
			return kevt, true, err
		}
		if i.yara != nil && kevt.Type == ktypes.LoadImage {
			// scan the the target filename
			go func() {
				imageYaraScans.Add(1)
				err := i.yara.ScanFile(filename, kevt)
				if err != nil {
					log.Warnf("unable to run yara scanner on %s image: %v", filename, err)
				}
			}()
		}
		if kevt.Type != ktypes.UnloadImage {
			return kevt, false, i.snap.Write(kevt)
		}
		return kevt, false, i.snap.Remove(kevt)
	}

	return kevt, true, nil
}

func (imageInterceptor) Close() {}
