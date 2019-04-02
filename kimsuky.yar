rule Excution_file : RAT Malware logging behavior
{
	strings:
      $Start_logging = "MZ" nocase wide ascii
	condition:
      all of them
}

rule logging : RAT Malware logging behavior
{
	meta:
		author = "Mook_k"
		date = "2019-04-02"
		filetype = "Win32 EXE"
		version = "1.0"
		SHA = "D02A38DA63E1E59380B1ABABC76D701D019A6336A31CE9A7515607763E4B5D19"
		type = "RAT"
		description = "Kimsuky Operation RAT Malware logging behavior detection"
	strings:
      $Start_logging = "Start Initializing" nocase wide ascii
      $Thread_Fail_logging = "GetAmmyyIdThread Failed" nocase wide ascii
      $Upload_logging = "UpLoad End" nocase wide ascii
	condition:
      all of them
}

rule Encoding : RAT Malware Encoding loop
{
	meta:
		author = "Mook_k"
		date = "2019-04-02"
		filetype = "Win32 EXE"
		version = "1.0"
		SHA = "D02A38DA63E1E59380B1ABABC76D701D019A6336A31CE9A7515607763E4B5D19"
		type = "RAT"
		description = "Kimsuky Operation Signature"
	strings:
      $Mutex_name = "www.GoldDragon.com" nocase wide 
	condition:
      all of them
}

rule special_charator : RAT Malware Encoding loop
{
	meta:
		author = "Mook_k"
		date = "2019-04-02"
		filetype = "Win32 EXE"
		SHA = "D02A38DA63E1E59380B1ABABC76D701D019A6336A31CE9A7515607763E4B5D19"
		type = "RAT"
		description = "Kimsuky Operation Signature"
	strings:
		$Mutex_name = 
		{(6F|62|61|6D|61|66|6F|78) [0-12] 
		 (6F|62|61|6D|61|66|6F|78) [0-12]
		 (6F|62|61|6D|61|66|6F|78) [0-12]
		 (6F|62|61|6D|61|66|6F|78) [0-12] 
		 (6F|62|61|6D|61|66|6F|78) [0-12] 
		 (6F|62|61|6D|61|66|6F|78) [0-12] 
		 (6F|62|61|6D|61|66|6F|78) [0-12] 
		 (6F|62|61|6D|61|66|6F|78)
		} //obamafox 스트링
		//$test1 = "\\Microsoft\\HNC\\"
		//$test2 = "%s1.hwp"
	condition:
      all of them
}

rule Fileless_kimsuky : RAT Malware Kimsuky Fileless Signature
{
	meta:
		author = "Mook_k"
		date = "2019-04-02"
		filetype = "Win32 EXE"
		SHA = "D02A38DA63E1E59380B1ABABC76D701D019A6336A31CE9A7515607763E4B5D19"
		type = "RAT"
		description = "Kimsuky Operation Signature"
	strings:

		/*
			"Kernel32.Dll" =  4B 65 72 6E 65 6C 33 32 2E 44 6C 6C 
			"WriteProcessMemory" = 57 72 69 74  65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 
			"SetThreadContext" = 53 65 74 54 68 72 65 61  64 43 6F 6E 74 65 78 74
			"GetThreadContext" = 47 65 74 54 68 72 65 61 64 43 6F 6E  74 65 78 74 
			"CreateProcessA" = 43 72 65 61 74 65 50 72 6F 63 65 73  73 41 
			"CreateProcessInternalA" = 43 72 65 61  74 65 50 72 6F 63 65 73 73 49 6E 74 65 72 6E 61 6C
		*/

		$Fileless_check = 
		{((4B 65 72 6E 65 6C 33 32 2E 44 6C 6C )|(57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79)|(53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 41)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 49 6E 74 65 72 6E 61 6C)) [0-30] 

		((4B 65 72 6E 65 6C 33 32 2E 44 6C 6C )|(57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79)|(53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 41)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 49 6E 74 65 72 6E 61 6C)) [0-30] 

		((4B 65 72 6E 65 6C 33 32 2E 44 6C 6C )|(57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79)|(53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 41)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 49 6E 74 65 72 6E 61 6C)) [0-30] 

		((4B 65 72 6E 65 6C 33 32 2E 44 6C 6C )|(57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79)|(53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 41)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 49 6E 74 65 72 6E 61 6C)) [0-30] 

		((4B 65 72 6E 65 6C 33 32 2E 44 6C 6C )|(57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79)|(53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 41)|(43 72 65 61 74 65 50 72 6F 63 65 73 73 49 6E 74 65 72 6E 61 6C))}
	condition:
		$Fileless_check
}

rule TEST_YARA : RAT Malware Encoding loop
{
	meta:
		author = "Mook_k"
		date = "2019-04-02"
		filetype = "Win32 EXE"
		MD5 = "D02A38DA63E1E59380B1ABABC76D701D019A6336A31CE9A7515607763E4B5D19"
		type = "Kimsuky Operation Signature"
	strings:
      $Mutex_name = "ww.GoldDragon.com" nocase wide ascii
      $TEST2 = "ink.inkboom.co.kr" nocase wide ascii

      
	condition:
      all of them
}















