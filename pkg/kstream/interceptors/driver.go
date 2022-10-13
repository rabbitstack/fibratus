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

package interceptors

import (
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
)

type driverInterceptor struct {
	devMapper fs.DevMapper
}

func newDriverInterceptor(devMapper fs.DevMapper) KstreamInterceptor {
	return &driverInterceptor{devMapper: devMapper}
}

func (driverInterceptor) Name() InterceptorType { return Driver }
func (driverInterceptor) Close()                {}

func (d *driverInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Type == ktypes.LoadDriver {
		filename, _ := kevt.Kparams.GetString(kparams.ImageFilename)
		if err := kevt.Kparams.SetValue(kparams.ImageFilename, d.devMapper.Convert(filename)); err != nil {
			return kevt, true, err
		}
	}
	return kevt, true, nil
}
