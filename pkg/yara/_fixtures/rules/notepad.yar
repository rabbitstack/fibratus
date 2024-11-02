rule Np : T1 T2
{
	meta:
		severity = 50
		date = "2016-07"
		threat_name = "Notepad.Shell"
		id = "babf9101-1e6e-4268-a530-e99e2c905b0d"
	strings:
		$c1 = "Notepad" fullword ascii
	condition:
		$c1
}
