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

package cpython

import "errors"

var ipv4Class *PyObject
var ipv6Class *PyObject
var ipaddressFn *PyObject

func initializeIpFnAndClasses() error {
	mod, err := NewModule("ipaddress")
	if err != nil {
		return err
	}
	if mod.IsNull() {
		return errors.New("ipaddress module was not initialized")
	}

	ipaddressFn, err = mod.GetAttrString("ip_address")
	if err != nil {
		return err
	}
	ipv4Class, err = mod.GetAttrString("IPv4Address")
	if err != nil {
		return err
	}
	ipv6Class, err = mod.GetAttrString("IPv6Address")
	if err != nil {
		return err
	}

	return nil
}
