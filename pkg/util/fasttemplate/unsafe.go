/*
 *	The MIT License (MIT)
 *
 *	Copyright (c) 2015 Aliaksandr Valialkin
 *  Modifications Copyright (c) 2019-2020 by Nedim Sabic
 *
 *	Permission is hereby granted, free of charge, to any person obtaining a copy
 *	of this software and associated documentation files (the "Software"), to deal
 *	in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *	copies of the Software, and to permit persons to whom the Software is
 */

package fasttemplate

import (
	"unsafe"
)

func bytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

//nolint:govet
func stringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
