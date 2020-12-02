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

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

// MakeConfig builds a TLS config from the certificate, private/public key and the CA cert files.
func MakeConfig(certFile, keyFile, caFile string, insecureSkipVerify bool) (*tls.Config, error) {
	if certFile == "" && keyFile == "" && caFile == "" {
		return nil, nil
	}

	var cert tls.Certificate
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}

	// load certificate/key
	if certFile != "" && keyFile == "" {
		var err error
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	// load certificate issuing authority
	if caFile != "" {
		cpool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		ok := cpool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("fail to load certificate authority: %s", caFile)
		}
		tlsConfig.RootCAs = cpool
	}

	return tlsConfig, nil
}
