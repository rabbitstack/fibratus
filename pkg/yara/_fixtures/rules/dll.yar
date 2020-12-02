rule DLL : dll
{
	meta:
		severity = "Critical"
		date = "2020-07"
	strings:
		$c0 = "Go" fullword ascii
	condition:
		$c0
}