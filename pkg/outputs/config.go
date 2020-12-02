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

package outputs

import (
	"fmt"
	"github.com/spf13/pflag"
)

// Config contains the output configuration.
type Config struct {
	Type   Type
	Output interface{}
}

// TLSConfig stores the client TLS parameters.
type TLSConfig struct {
	// TLSCA represents the path of the certificate file that is associated with the Certification Authority (CA).
	TLSCA string `mapstructure:"tls-ca"`
	// TLSCert is the path to the certificate file.
	TLSCert string `mapstructure:"tls-cert"`
	// TLSKey represents the path to the public/private key file.
	TLSKey string `mapstructure:"tls-key"`
	// TLSInsecureSkipVerify skips the chain and host verification.
	TLSInsecureSkipVerify bool `mapstructure:"tls-insecure-skip-verify"`
}

// AddTLSFlags register the TLS flags for the specified output type.
func AddTLSFlags(flags *pflag.FlagSet, typ Type) {
	flags.String(tlsForOutput("tls-ca", typ), "", "Represents the path of the certificate file that is associated with the Certification Authority (CA)")
	flags.String(tlsForOutput("tls-cert", typ), "", "Path to certificate file")
	flags.String(tlsForOutput("tls-key", typ), "", "Path to the public/private key file")
	flags.Bool(tlsForOutput("tls-insecure-skip-verify", typ), false, "Indicates if the chain and host verification stage is skipped")
}

func tlsForOutput(name string, typ Type) string { return fmt.Sprintf("output.%s.%s", typ, name) }
