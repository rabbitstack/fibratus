/*
 *	Copyright 2019-2020 by Nedim Sabic
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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMatch(t *testing.T) {
	assert.True(t, Match("C:\\*\\lsass?.dmp", "C:\\Windows\\System32\\lsass2.dmp"))
	assert.True(t, Match("C:\\*\\ActionList.x?l", "C:\\Windows\\Setup\\LatentAcquisition\\ActionList.xml"))
	assert.True(t, Match("C:\\ProgramData\\*.dll", "C:\\ProgramData\\Directory\\OneMoreDirectory\\mal.dll"))
	assert.True(t, Match("C:\\ProgramData\\*.dll", "C:\\ProgramData\\Directory\\OneMoreDirectory\\mal.dll"))
	assert.True(t, Match("HKEY_USERS\\*\\Environment\\windir", "HKEY_USERS\\S-1-5-21-2271034452-2606270099-984871569-1001\\Environment\\windir"))
	assert.True(t, Match("C:\\Windows\\SoftwareDistribution\\*", "C:\\Windows\\SoftwareDistribution\\SLS\\7971F918-A847-4430-9279-4A52D1EFE18D\\sls.rar"))
}
