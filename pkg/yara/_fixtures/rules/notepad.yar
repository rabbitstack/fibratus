rule Notepad
{
	meta:
		severity = 50
		date = "2016-07"
		threat_name = "X.Notepad"
		id = "babf9101-1e6e-4268-a530-e99e2c905b0d"
	strings:
		$c0 = "Microsoft" fullword ascii
		$c1 = "Notepad" fullword ascii
	condition:
		$c0 and $c1
}
