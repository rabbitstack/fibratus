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
	"unicode"
	"unicode/utf8"
)

// Match performs ASCII-first, iterative wildcard matching with UTF-8 fallback.
// It supports '*' and '?' wildcards in the pattern string. If caseSensitive
// is false, comparisons are performed case-insensitively with zero extra
// allocations.
func Match(pattern, str string, caseSensitive bool) bool {
	if caseSensitive {
		return matchCaseSensitive(pattern, str)
	}
	return matchCaseInsensitive(pattern, str)
}

func matchCaseSensitive(pattern, str string) bool {
	slen, plen := len(str), len(pattern)
	var p, s int
	wildcardIdx, matchIdx := -1, 0

	for s < slen {
		if p < plen {
			pb := pattern[p]
			switch pb {
			case '?':
				// match exactly one character
				if str[s] < utf8.RuneSelf && pb < utf8.RuneSelf {
					p++
					s++
				} else {
					_, psize := utf8.DecodeRuneInString(pattern[p:])
					_, ssize := utf8.DecodeRuneInString(str[s:])
					p += psize
					s += ssize
				}
				continue
			case '*':
				wildcardIdx, matchIdx = p, s
				p++
				continue
			default:
				// literal match
				if pb < utf8.RuneSelf && str[s] < utf8.RuneSelf {
					if pb == str[s] { // direct compare, no function call, inlines trivially
						p++
						s++
						continue
					}
				} else {
					pr, psize := utf8.DecodeRuneInString(pattern[p:])
					sr, ssize := utf8.DecodeRuneInString(str[s:])
					if pr == sr {
						p += psize
						s += ssize
						continue
					}
				}
			}
		}
		if wildcardIdx != -1 {
			p = wildcardIdx + 1
			matchIdx++
			s = matchIdx
			continue
		}
		return false
	}
	for p < plen && pattern[p] == '*' {
		p++
	}
	return p == plen
}

func matchCaseInsensitive(pattern, str string) bool {
	slen, plen := len(str), len(pattern)
	var p, s int
	wildcardIdx, matchIdx := -1, 0

	for s < slen {
		if p < plen {
			pb := pattern[p]
			switch pb {
			case '?':
				if str[s] < utf8.RuneSelf && pb < utf8.RuneSelf {
					p++
					s++
				} else {
					_, psize := utf8.DecodeRuneInString(pattern[p:])
					_, ssize := utf8.DecodeRuneInString(str[s:])
					p += psize
					s += ssize
				}
				continue
			case '*':
				wildcardIdx, matchIdx = p, s
				p++
				continue
			default:
				if pb < utf8.RuneSelf && str[s] < utf8.RuneSelf {
					if pb == str[s] || foldASCII(pb) == foldASCII(str[s]) { // pb==str[s] short-circuits the common exact-match case
						p++
						s++
						continue
					}
				} else {
					pr, psize := utf8.DecodeRuneInString(pattern[p:])
					sr, ssize := utf8.DecodeRuneInString(str[s:])
					if pr == sr || unicode.ToLower(pr) == unicode.ToLower(sr) {
						p += psize
						s += ssize
						continue
					}
				}
			}
		}
		if wildcardIdx != -1 {
			p = wildcardIdx + 1
			matchIdx++
			s = matchIdx
			continue
		}
		return false
	}
	for p < plen && pattern[p] == '*' {
		p++
	}
	return p == plen
}

func foldASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
