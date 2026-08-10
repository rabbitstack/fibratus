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

package event

import (
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
)

// ViewSectionTypes describes possible values for process mapped sections.
var ViewSectionTypes = ParamEnum{
	va.SectionData:           "DATA",
	va.SectionImage:          "IMAGE",
	va.SectionImageNoExecute: "IMAGE_NO_EXECUTE",
	va.SectionPagefile:       "PAGEFILE",
	va.SectionPhysical:       "PHYSICAL",
}

// DNSRecordTypes describes DNS record type values.
var DNSRecordTypes = ParamEnum{
	windows.DNS_TYPE_A:       "A",
	windows.DNS_TYPE_NS:      "NS",
	windows.DNS_TYPE_MD:      "MD",
	windows.DNS_TYPE_MF:      "MF",
	windows.DNS_TYPE_CNAME:   "CNAME",
	windows.DNS_TYPE_SOA:     "SOA",
	windows.DNS_TYPE_MB:      "MB",
	windows.DNS_TYPE_MG:      "MG",
	windows.DNS_TYPE_MR:      "MR",
	windows.DNS_TYPE_NULL:    "NULL",
	windows.DNS_TYPE_WKS:     "WKS",
	windows.DNS_TYPE_PTR:     "PTR",
	windows.DNS_TYPE_HINFO:   "HINFO",
	windows.DNS_TYPE_MINFO:   "MINFO",
	windows.DNS_TYPE_MX:      "MX",
	windows.DNS_TYPE_TEXT:    "TEXT",
	windows.DNS_TYPE_RP:      "RP",
	windows.DNS_TYPE_AFSDB:   "AFSDB",
	windows.DNS_TYPE_X25:     "X25",
	windows.DNS_TYPE_ISDN:    "ISDN",
	windows.DNS_TYPE_NSAPPTR: "NSAPPTR",
	windows.DNS_TYPE_SIG:     "SIG",
	windows.DNS_TYPE_KEY:     "KEY",
	windows.DNS_TYPE_PX:      "PX",
	windows.DNS_TYPE_GPOS:    "GPOS",
	windows.DNS_TYPE_AAAA:    "AAAA",
	windows.DNS_TYPE_LOC:     "LOC",
	windows.DNS_TYPE_NXT:     "NXT",
	windows.DNS_TYPE_EID:     "EID",
	windows.DNS_TYPE_NIMLOC:  "NIMLOC",
	windows.DNS_TYPE_SRV:     "SRV",
	windows.DNS_TYPE_ATMA:    "ATMA",
	windows.DNS_TYPE_NAPTR:   "NAPTR",
	windows.DNS_TYPE_KX:      "KX",
	windows.DNS_TYPE_CERT:    "CERT",
	windows.DNS_TYPE_A6:      "A6",
	windows.DNS_TYPE_DNAME:   "DNAME",
	windows.DNS_TYPE_SINK:    "SINK",
	windows.DNS_TYPE_OPT:     "OPT",
	windows.DNS_TYPE_DS:      "DS",
	windows.DNS_TYPE_RRSIG:   "RRSIG",
	windows.DNS_TYPE_NSEC:    "NSEC",
	windows.DNS_TYPE_DNSKEY:  "DNSKEY",
	windows.DNS_TYPE_DHCID:   "DHCID",
	windows.DNS_TYPE_UINFO:   "UINFO",
	windows.DNS_TYPE_UID:     "UID",
	windows.DNS_TYPE_GID:     "GID",
	windows.DNS_TYPE_UNSPEC:  "UNSPEC",
	windows.DNS_TYPE_ADDRS:   "ADDRS",
	windows.DNS_TYPE_TKEY:    "TKEY",
	windows.DNS_TYPE_TSIG:    "TSIG",
	windows.DNS_TYPE_IXFR:    "IXFR",
	windows.DNS_TYPE_AXFR:    "AXFR",
	windows.DNS_TYPE_MAILB:   "MAILB",
	windows.DNS_TYPE_MAILA:   "MAILA",
	windows.DNS_TYPE_ANY:     "ANY",
	windows.DNS_TYPE_WINS:    "WINS",
	windows.DNS_TYPE_WINSR:   "WINSR",
}

// DNSResponseCodes describes DNS response codes.
var DNSResponseCodes = ParamEnum{
	uint32(windows.DNS_ERROR_RCODE_NO_ERROR):        "NOERROR",
	uint32(windows.DNS_ERROR_RCODE_FORMAT_ERROR):    "FORMERR",
	uint32(windows.DNS_ERROR_RCODE_SERVER_FAILURE):  "SERVFAIL",
	uint32(windows.DNS_ERROR_RCODE_NAME_ERROR):      "NXDOMAIN",
	uint32(windows.DNS_ERROR_RCODE_NOT_IMPLEMENTED): "NOTIMP",
	uint32(windows.DNS_ERROR_RCODE_REFUSED):         "REFUSED",
	uint32(windows.DNS_ERROR_RCODE_YXDOMAIN):        "YXDOMAIN",
	uint32(windows.DNS_ERROR_RCODE_YXRRSET):         "YXRRSET",
	uint32(windows.DNS_ERROR_RCODE_NXRRSET):         "NXRRSET",
	uint32(windows.DNS_ERROR_RCODE_NOTAUTH):         "NOTAUTH",
	uint32(windows.DNS_ERROR_RCODE_NOTZONE):         "NOTZONE",
	uint32(windows.DNS_ERROR_RCODE_BADSIG):          "BADSIG",
	uint32(windows.DNS_ERROR_RCODE_BADKEY):          "BADKEY",
	uint32(windows.DNS_ERROR_RCODE_BADTIME):         "BADTIME",
	uint32(windows.DNS_ERROR_INVALID_NAME):          "BADNAME",
	uint32(windows.ERROR_INVALID_PARAMETER):         "INVALID",
	uint32(windows.DNS_INFO_NO_RECORDS):             "NXDOMAIN",
}

const (
	TokenElevationTypeDefault uint32 = iota + 1
	TokenElevationTypeFull
	TokenElevationTypeLimited
)

// PsTokenElevationTypes describes process token elevation types
var PsTokenElevationTypes = ParamEnum{
	TokenElevationTypeDefault: "DEFAULT",
	TokenElevationTypeFull:    "FULL",
	TokenElevationTypeLimited: "LIMITED",
}
