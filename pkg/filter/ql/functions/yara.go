//go:build yara
// +build yara

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

package functions

import (
	"fmt"
	"github.com/hillu/go-yara/v4"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

// scanTimeout specifies the timeout interval for the scan operation
const scanTimeout = time.Second * 10

// Yara provides signature-based detection in filters and rules.
// YARA is a tool aimed at (but not limited to) helping malware
// researchers to identify and classify malware samples. With YARA
// you can create descriptions of malware families based on textual
// or binary patterns. Depending on the parameter type supplied to this
// function, the scan can be performed on the process, filename or a
// memory block.
type Yara struct{}

func (f Yara) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 2 {
		return false, false
	}
	var rules string
	var vars map[string]interface{}
	switch r := args[1].(type) {
	case string:
		rules = r
	case []string:
		rules = strings.Join(r, " ")
	}
	if len(args) > 3 {
		vars, _ = args[2].(map[string]interface{})
	}
	scanner, err := f.newScanner(rules, vars)
	if err != nil {
		log.Warnf("erroneous scanner for Yara rule(s): %v: %s", err, rules)
		return false, true
	}
	defer scanner.Destroy()

	var cb yara.MatchRules
	switch n := args[0].(type) {
	case uint32: // pid
		err = scanner.SetCallback(&cb).ScanProc(int(n))
	case string: // file
		err = scanner.SetCallback(&cb).ScanFile(n)
	case []byte: // mem block
		err = scanner.SetCallback(&cb).ScanMem(n)
	default: // invalid type
		return false, false
	}
	if err != nil {
		return false, true
	}
	return len(cb) > 0, true
}

func (f Yara) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: YaraFn,
		Args: []FunctionArgDesc{
			{Keyword: "pid|file|bytes", Types: []ArgType{Field, Func, String, Number}, Required: true},
			{Keyword: "rules", Types: []ArgType{Field, Func, String}, Required: true},
			{Keyword: "vars", Types: []ArgType{Field, Func, String}},
		},
	}
	return desc
}

func (f Yara) Name() Fn { return YaraFn }

func (f Yara) newScanner(rules string, vars map[string]interface{}) (*yara.Scanner, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	defer c.Destroy()
	if err := c.AddString(rules, ""); err != nil {
		return nil, err
	}
	for k, v := range vars {
		if err := c.DefineVariable(k, v); err != nil {
			return nil, err
		}
	}
	if len(c.Errors) > 0 {
		return nil, parseCompilerErrors(c.Errors)
	}
	r, err := c.GetRules()
	if err != nil {
		return nil, err
	}
	scanner, err := yara.NewScanner(r)
	if err != nil {
		return nil, err
	}
	scanner.SetFlags(yara.ScanFlagsFastMode)
	scanner.SetTimeout(scanTimeout)
	return scanner, nil
}

func parseCompilerErrors(errors []yara.CompilerMessage) error {
	errs := make([]error, len(errors))
	for i, err := range errors {
		errs[i] = fmt.Errorf("%s, line: %d", err.Text, err.Line)
	}
	return multierror.Wrap(errs...)
}
