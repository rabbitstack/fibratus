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

package markdown

import "regexp"

// All credits go to https://github.com/writeas/go-strip-markdown/blob/master/strip.go

var (
	listLeadersReg = regexp.MustCompile(`(?m)^([\s\t]*)([\*\-\+]|\d\.)\s+`)

	headerReg = regexp.MustCompile(`\n={2,}`)
	strikeReg = regexp.MustCompile(`~~`)
	codeReg   = regexp.MustCompile("`{3}" + `.*\n`)

	htmlReg         = regexp.MustCompile("<(.*?)>")
	emphReg         = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	emphReg2        = regexp.MustCompile(`\*([^*]+)\*`)
	emphReg3        = regexp.MustCompile(`__([^_]+)__`)
	emphReg4        = regexp.MustCompile(`_([^_]+)_`)
	setextHeaderReg = regexp.MustCompile(`^[=\-]{2,}\s*$`)
	footnotesReg    = regexp.MustCompile(`\[\^.+?\](\: .*?$)?`)
	footnotes2Reg   = regexp.MustCompile(`\s{0,2}\[.*?\]: .*?$`)
	imagesReg       = regexp.MustCompile(`\!\[(.*?)\]\s?[\[\(].*?[\]\)]`)
	linksReg        = regexp.MustCompile(`\[(.*?)\][\[\(].*?[\]\)]`)
	blockquoteReg   = regexp.MustCompile(`>\s*`)
	refLinkReg      = regexp.MustCompile(`^\s{1,2}\[(.*?)\]: (\S+)( ".*?")?\s*$`)
	atxHeaderReg    = regexp.MustCompile(`(?m)^\#{1,6}\s*([^#]+)\s*(\#{1,6})?$`)
	atxHeaderReg2   = regexp.MustCompile(`([\*_]{1,3})(\S.*?\S)?P1`)
	atxHeaderReg3   = regexp.MustCompile("(?m)(`{3,})" + `(.*?)?P1`)
	atxHeaderReg4   = regexp.MustCompile(`^-{3,}\s*$`)
	atxHeaderReg5   = regexp.MustCompile("`(.+?)`")
	atxHeaderReg6   = regexp.MustCompile(`\n{2,}`)
)

// Strip returns the given string sans any Markdown.
// Where necessary, elements are replaced with their best textual forms, so
// for example, hyperlinks are stripped of their URL and become only the link
// text, and images lose their URL and become only the alt text.
func Strip(md string) string {
	s := md
	s = listLeadersReg.ReplaceAllString(s, "$1")

	s = headerReg.ReplaceAllString(s, "\n")
	s = strikeReg.ReplaceAllString(s, "")
	s = codeReg.ReplaceAllString(s, "")

	s = emphReg.ReplaceAllString(s, "$1")
	s = emphReg2.ReplaceAllString(s, "$1")
	s = emphReg3.ReplaceAllString(s, "$1")
	s = emphReg4.ReplaceAllString(s, "$1")
	s = htmlReg.ReplaceAllString(s, "$1")
	s = setextHeaderReg.ReplaceAllString(s, "")
	s = footnotesReg.ReplaceAllString(s, "")
	s = footnotes2Reg.ReplaceAllString(s, "")

	s = imagesReg.ReplaceAllString(s, "")

	s = linksReg.ReplaceAllString(s, "$1")
	s = blockquoteReg.ReplaceAllString(s, "  ")
	s = refLinkReg.ReplaceAllString(s, "")
	s = atxHeaderReg.ReplaceAllString(s, "$1")
	s = atxHeaderReg2.ReplaceAllString(s, "$2")
	s = atxHeaderReg3.ReplaceAllString(s, "$2")
	s = atxHeaderReg4.ReplaceAllString(s, "")
	s = atxHeaderReg5.ReplaceAllString(s, "$1")
	s = atxHeaderReg6.ReplaceAllString(s, "\n\n")

	return s
}
