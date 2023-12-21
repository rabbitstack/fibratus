rule Notepad : notepad
{
	meta:
		severity = "Normal"
		date = "2016-07"
	strings:
		$c0 = "Notepad" fullword ascii
	condition:
		$c0
}

rule NotepadCompany
{
	meta:
		severity = "Normal"
		date = "2016-07"
	strings:
		$c0 = "Microsoft" fullword ascii
	condition:
		$c0
}