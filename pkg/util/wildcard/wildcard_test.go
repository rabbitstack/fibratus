/*
 *	Copyright 2019-present by Nedim Sabic
 *	http://rabbitstack.github.io
 *	All Rights Reserved.
 *
 *	Licensed under the Apache License, Version 2.0 (the "License"); you may
 *	not use this file except in compliance with the License. You may obtain
 *	a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 */

package wildcard

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatch(t *testing.T) {
	var tests = []struct {
		p     string
		s     string
		match bool
	}{
		{"C:\\*\\lsass?.dmp", "C:\\Windows\\System32\\lsass2.dmp", true},
		{"?:\\*\\lsass?.dmp", "C:\\Windows\\System32\\lsass2.dmp", true},
		{"?:\\*\\lsass?.dmp", "C:\\Windows\\System32\\cmd.exe", false},
		{"C:\\*\\ActionList.x?l", "C:\\Windows\\Setup\\LatentAcquisition\\ActionList.xml", true},
		{"C:\\ProgramData\\*.dll", "C:\\ProgramData\\Directory\\OneMoreDirectory\\mal.dll", true},
		{"HKEY_USERS\\*\\Environment\\windir", "HKEY_USERS\\S-1-5-21-2271034452-2606270099-984871569-1001\\Environment\\windir", true},
		{"C:\\Windows\\SoftwareDistribution\\*", "C:\\Windows\\SoftwareDistribution\\SLS\\7971F918-A847-4430-9279-4A52D1EFE18D\\sls.rar", true},
		{"HKEY_USERS\\S-1-5-21-*_CLASSES\\MS-SETTINGS\\CURVER", "HKEY_USERS\\S-1-5-21-2271034452-1207270099-244871569-1021_CLASSES\\MS-SETTINGS\\CURVER", true},
		{"ntdll.dll|KernelBase.dll|advapi32.dll|*", "ntdll.dll|KernelBase.dll|advapi32.dll|pe386.dll|com.dll|clr.dll|mmc.exe", true},
	}

	for _, tt := range tests {
		t.Run(tt.p, func(t *testing.T) {
			assert.Equal(t, tt.match, Match(tt.p, tt.s))
		})
	}
}
