rule Regedit : T1
{
	meta:
		severity = 50
		date = "2016-07"
		threat_name = "Regedit"
		id = "1abf9101-1e6e-4268-a530-e99e2c905b0d"
	strings:
		$c1 = "Regedit" nocase fullword ascii
	condition:
		$c1
}
