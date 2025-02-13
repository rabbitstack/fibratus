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

package config

import (
	"github.com/mitchellh/mapstructure"
	"net"
	"reflect"
)

func decode(input, output interface{}) error {
	var decoderConfig = &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			ipSliceDecodeHook(),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return err
	}
	return decoder.Decode(input)
}

func ipSliceDecodeHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if to.Kind() == reflect.Slice && to.Elem() == reflect.TypeOf(net.IP(nil)) {
			switch v := data.(type) {
			case []interface{}:
				var ips []net.IP
				for _, s := range v {
					ip, ok := s.(string)
					if !ok {
						continue
					}
					ips = append(ips, net.ParseIP(ip))
				}
				return ips, nil
			}
		}

		return data, nil
	}
}
