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

package formatter

import (
	"fmt"
	"github.com/antchfx/htmlquery"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pex "github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	shandle "github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

func init() {
	version.Set("1.7.0")
}

func TestHTMLFormatterRuleAlert(t *testing.T) {
	f := HTML{}
	out, err := f.FormatRuleAlert(&config.ActionContext{
		Group: config.FilterGroup{
			Description: "Identifies attempts from adversaries to acquire credentials from Vault files.",
			Labels: map[string]string{
				"tactic.name":       "Credential Access",
				"tactic.ref":        "https://attack.mitre.org/tactics/TA0006/",
				"technique.name":    "Credentials from Password Stores",
				"technique.ref":     "https://attack.mitre.org/techniques/T1555/",
				"subtechnique.name": "Windows Credential Manager",
				"subtechnique.ref":  "https://attack.mitre.org/techniques/T1555/004/",
			},
		},
		Events: []*kevent.Kevent{
			{
				Type:        ktypes.CreateFile,
				Tid:         2484,
				PID:         859,
				CPU:         1,
				Seq:         2,
				Name:        "CreateFile",
				Timestamp:   time.Now(),
				Category:    ktypes.File,
				Host:        "archrabbit",
				Description: "Creates or opens a new file, directory, I/O device, pipe, console",
				Kparams: kevent.Kparams{
					kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
					kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
					kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
					kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: fs.FileDisposition(1)},
				},
				Metadata: map[kevent.MetadataKey]string{"foo": "bar", "fooz": "barzz"},
				PS: &pstypes.PS{
					PID:  2436,
					Ppid: 6304,
					Parent: &pstypes.PS{
						PID:  2034,
						Name: "explorer.exe",
						Exe:  `C:\Windows\System32\explorer.exe`,
						Cwd:  `C:\Windows\System32`,
						SID:  "admin\\SYSTEM",
						Parent: &pstypes.PS{
							PID:  2345,
							Name: "winlogon.exe",
						},
					},
					Name:      "firefox.exe",
					Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
					Comm:      `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
					Cwd:       `C:\Program Files\Mozilla Firefox\`,
					SID:       "archrabbit\\SYSTEM",
					Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
					SessionID: 4,
					Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
					Threads: map[uint32]pstypes.Thread{
						3453: {Tid: 3453, Entrypoint: kparams.Hex("0x7ffe2557ff80"), IOPrio: 2, PagePrio: 5, KstackBase: kparams.Hex("0xffffc307810d6000"), KstackLimit: kparams.Hex("0xffffc307810cf000"), UstackLimit: kparams.Hex("0x5260000"), UstackBase: kparams.Hex("0x525f000")},
						3455: {Tid: 3455, Entrypoint: kparams.Hex("0x5efe2557ff80"), IOPrio: 3, PagePrio: 5, KstackBase: kparams.Hex("0xffffc307810d6000"), KstackLimit: kparams.Hex("0xffffc307810cf000"), UstackLimit: kparams.Hex("0x5260000"), UstackBase: kparams.Hex("0x525f000")},
					},
					Modules: []pstypes.Module{
						{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 1233405456},
						{Name: "C:\\Windows\\System32\\ntdll.dll", Size: 133405456},
						{Name: "C:\\Windows\\System32\\shell32.dll", Size: 33405456},
					},
					Handles: []htypes.Handle{
						{Num: shandle.Handle(0xffffd105e9baaf70),
							Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
							Type:   "Key",
							Object: 777488883434455544,
							Pid:    uint32(1023),
						},
						{
							Num:  shandle.Handle(0xffffd105e9adaf70),
							Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
							Type: "ALPC Port",
							Pid:  uint32(1023),
							MD: &htypes.AlpcPortInfo{
								Seqno:   1,
								Context: 0x0,
								Flags:   0x0,
							},
							Object: 457488883434455544,
						},
						{
							Num:  shandle.Handle(0xeaffd105e9adaf30),
							Name: `C:\Users\bunny`,
							Type: "File",
							Pid:  uint32(1023),
							MD: &htypes.FileInfo{
								IsDirectory: true,
							},
							Object: 357488883434455544,
						},
					},
					PE: &pex.PE{
						NumberOfSections: 2,
						NumberOfSymbols:  10,
						EntryPoint:       "0x20110",
						ImageBase:        "0x140000000",
						LinkTime:         time.Now(),
						Sections: []pex.Sec{
							{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
							{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
						},
						Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
						Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
						VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
					},
				},
			},
			{
				Type:        ktypes.CreateProcess,
				Tid:         2184,
				PID:         1022,
				CPU:         2,
				Seq:         3,
				Name:        "CreateProcess",
				Timestamp:   time.Now(),
				Category:    ktypes.File,
				Host:        "archrabbit",
				Description: "Creates a new process",
				Kparams: kevent.Kparams{
					kparams.Comm:    {Name: kparams.Comm, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
					kparams.Exe:     {Name: kparams.Exe, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe"},
					kparams.UserSID: {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: "admin\\SYSTEM"},
				},
				Metadata: map[kevent.MetadataKey]string{"foo": "bar", "fooz": "barzz"},
				PS: &pstypes.PS{
					PID:  2436,
					Ppid: 6304,
					Parent: &pstypes.PS{
						PID:  2034,
						Name: "explorer.exe",
						Exe:  `C:\Windows\System32\explorer.exe`,
						Cwd:  `C:\Windows\System32`,
						SID:  "admin\\SYSTEM",
						Parent: &pstypes.PS{
							PID:  2345,
							Name: "winlogon.exe",
						},
					},
					Name:      "firefox.exe",
					Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
					Comm:      `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
					Cwd:       `C:\Program Files\Mozilla Firefox\`,
					SID:       "archrabbit\\SYSTEM",
					Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
					SessionID: 4,
					Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
					Threads: map[uint32]pstypes.Thread{
						3453: {Tid: 3453, Entrypoint: kparams.Hex("0x7ffe2557ff80"), IOPrio: 2, PagePrio: 5, KstackBase: kparams.Hex("0xffffc307810d6000"), KstackLimit: kparams.Hex("0xffffc307810cf000"), UstackLimit: kparams.Hex("0x5260000"), UstackBase: kparams.Hex("0x525f000")},
						3455: {Tid: 3455, Entrypoint: kparams.Hex("0x5efe2557ff80"), IOPrio: 3, PagePrio: 5, KstackBase: kparams.Hex("0xffffc307810d6000"), KstackLimit: kparams.Hex("0xffffc307810cf000"), UstackLimit: kparams.Hex("0x5260000"), UstackBase: kparams.Hex("0x525f000")},
					},
					Modules: []pstypes.Module{
						{Name: "C:\\Windows\\System32\\kernel32.dll", Size: 1233405456},
						{Name: "C:\\Windows\\System32\\ntdll.dll", Size: 133405456},
						{Name: "C:\\Windows\\System32\\shell32.dll", Size: 33405456},
					},
					Handles: []htypes.Handle{
						{Num: shandle.Handle(0xffffd105e9baaf70),
							Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
							Type:   "Key",
							Object: 777488883434455544,
							Pid:    uint32(1023),
						},
						{
							Num:  shandle.Handle(0xffffd105e9adaf70),
							Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
							Type: "ALPC Port",
							Pid:  uint32(1023),
							MD: &htypes.AlpcPortInfo{
								Seqno:   1,
								Context: 0x0,
								Flags:   0x0,
							},
							Object: 457488883434455544,
						},
						{
							Num:  shandle.Handle(0xeaffd105e9adaf30),
							Name: `C:\Users\bunny`,
							Type: "File",
							Pid:  uint32(1023),
							MD: &htypes.FileInfo{
								IsDirectory: true,
							},
							Object: 357488883434455544,
						},
					},
					PE: &pex.PE{
						NumberOfSections: 2,
						NumberOfSymbols:  10,
						EntryPoint:       "0x20110",
						ImageBase:        "0x140000000",
						LinkTime:         time.Now(),
						Sections: []pex.Sec{
							{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
							{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
						},
						Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
						Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
						VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
					},
				},
			},
		},
	},
		alertsender.Alert{
			Title:    "Suspicious access to Windows Vault files",
			Severity: alertsender.Critical})
	require.NoError(t, err)
	ioutil.WriteFile("alert.html", []byte(out), os.ModePerm)
	doc, err := htmlquery.Parse(strings.NewReader(out))
	require.NoError(t, err)

	fmt.Println(doc)
}
