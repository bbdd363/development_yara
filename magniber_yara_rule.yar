rule Mutex_name : Mutex Name detect rule
{
      meta:
            author = "Mook_k"
            date = "2018-11-25"
            filetype = "Win32 EXE"
            MD5 = 40A5312F203F48759CBC1C08F91C499A"
            type = "Gryphone Ransomeware"
      strings:
      $Mutex_name = "DEMONSLAY335QQ" nocase wide ascii
      condition:
      all of them
}

rule shellcode : shellcode content
{
      meta:
              author = "Mook_k"
              filetype = "Win32 EXE"
              date = "2018-11-25"
              MD5 = 40A5312F203F48759CBC1C08F91C499A"
              type = "Gryphone Ransomeware"
      strings:
        $shellcode_1 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" nocase wide ascii
      $shellcode_2 = "/c bcdedit.exe /set {default} recoveryenabled No" nocase wide ascii
      $shellcode_3 = "/c vssadmin.exe Delete Shadows /All /Quiet" nocase wide ascii
      condition:
            1 of ($shellcode_*)
}


rule white_list
{
      meta:
            author = "Mook_k"
            filetype = "Win32 EXE"
            date = "2018-11-25"
            MD5 = 40A5312F203F48759CBC1C08F91C499A"
            type = "Gryphone Ransomeware"
      
      strings:
            $white_file_name_1 = "gryphon" nocase wide ascii
            $white_file_name_2 = ".gryphon" nocase wide ascii
            $white_file_name_3 = "BOOTMGR" nocase wide ascii
            $white_file_name_4 = "!## DECRYPT FILES ##!.txt" nocase wide ascii
            
            $white_list_1 = "program files (x86)" nocase wide ascii
            $white_list_2 = "program files" nocase wide ascii
            $white_list_3 = "temp" nocase wide ascii
            $white_list_4 = "inetpub" nocase wide ascii
            $white_list_5 = "appdata" nocase wide ascii
            $white_list_6 = "windows" nocase wide ascii
            $white_list_7 = "programdata\\" nocase wide ascii
            $white_list_8 = "programdata" nocase wide ascii
            $white_list_9 = "ProgramData" nocase wide ascii
            $white_list_10 = "msocache" nocase wide ascii
            $white_list_11 = "$recycle.bin" nocase wide ascii
            $white_list_12 = ".." nocase wide ascii
            $white_list_13 = "." nocase wide ascii
            $white_list_14 = "intel" nocase wide ascii
            $white_list_15 = "nvidia" nocase wide ascii
      
      condition:
            2 of ($white_file_name_*) and  7 of ($white_list_*)
}


rule destination_email : hacker want send money this destination_email
{
      meta:
            author = "Mook_k"
            filetype = "Win32 EXE"
            date = "2018-11-25"
            MD5 = 40A5312F203F48759CBC1C08F91C499A"
            type = "Gryphone Ransomeware"
      
      strings:
            $test_0 = "ZWRpc3R2ZW5peV9kZWNvZGVyQGFvbC5jb20=" nocase wide ascii
            $test_0 = edistveniy_decoder@aol.com      
      condition:
            1 of them
}

rule encoding_ransomenote
{
      meta: 
            author = "Mook_k"
            filetype = "Win32 EXE"
            date = "2018-11-25"
            MD5 = 40A5312F203F48759CBC1C08F91C499A"
            type = "Gryphone Ransomeware"
      
      strings:
            $encoding_ransomenote_1 = "0pVSha3RdFA38b7pvn34PwtH7tgGxmauYbrg+z9tKeRCqlZ3dUj+RLn+BbwjqE6cPZnR4ziLFrrcJTdAiAV9NVTKnoVU//Wm/cozIsXP5hu+aBGnnMAWS+ViD5Sal2DS08MfGrnr6C64Zm+tZKmAYpNf+o98e4sFozfymqITlbY=" nocase wide ascii
            $encoding_ransomenote_2 = "DQo9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gR1JZUEhPTiBSQU5TT01XQVJFID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQ==" nocase wide ascii
            $encoding_ransomenote_3 = "0pVSha3RdFA38b7pvn34PwtH7tgGxmauYbrg+z9tKeRCqlZ3dUj+RLn+BbwjqE6cPZnR4ziLFrrcJTdAiAV9NVTKnoVU//Wm/cozIsXP5hu+aBGnnMAWS+ViD5Sal2DS08MfGrnr6C64Zm+tZKmAYpNf+o98e4sFozfymqITlbY=" nocase wide ascii
            $encoding_ransomenote_4 = "0pVSha3RdFA38b7pvn34PwtH7tgGxmauYbrg+z9tKeRCqlZ3dUj+RLn+BbwjqE6cPZnR4ziLFrrcJTdA" nocase wide ascii
            $encoding_ransomenote_5 = "iAV9NVTKnoVU//Wm/cozIsXP5hu+aBGnnMAWS+ViD5Sal2DS08MfGrnr6C64Zm+tZKmAYpNf+o98e4sFozfymqITlbY=" nocase wide ascii
            $encoding_ransomenote_6 = "PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09IEdSWVBIT04gUkFOU09NV0FSRSA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0NCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQUxMIFlPVVIgRklMRVMgSEFWRSBCRUVOIEVOQ1JZUFRFRA0KDQpBbGwgeW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVkIGR1ZSB0byBhIHNlY3VyaXR5IHByb2JsZW0gd2l0aCB5b3VyIFBDLg0KSWYgeW91IHdhbnQgdG8gcmVzdG9yZSB0aGVtLCB3cml0ZSB1cyB0byB0aGUgZS1tYWlsOiA=" nocase wide ascii
            $encoding_ransomenote_7 = "WW91IGhhdmUgdG8gcGF5IGZvciBkZWNyeXB0aW9uIGluIEJpdGNvaW5zLiBUaGUgcHJpY2UgZGVwZW5kcyBvbiBob3cgZmFzdCB5b3Ugd3JpdGUgdG8gdXMuDQpBZnRlciBwYXltZW50IHdlIHdpbGwgc2VuZCB5b3UgdGhlIGRlY3J5cHRpb24gdG9vbCB0aGF0IHdpbGwgZGVjcnlwdCBhbGwgeW91ciBmaWxlcy4NCg0KRnJlZSBkZWNyeXB0aW9uIGFzIGd1YXJhbnRlZQ0KICBCZWZvcmUgcGF5aW5nIHlvdSBjYW4gc2VuZCB0byB1cyB1cCB0byAzIGZpbGVzIGZvciBmcmVlIGRlY3J5cHRpb24uDQogIFBsZWFzZSBub3RlIHRoYXQgZmlsZXMgbXVzdCBOT1QgY29udGFpbiB2YWx1YWJsZSBpbmZvcm1hdGlvbiBhbmQgdGhlaXIgdG90YWwgc2l6ZQ0KICBtdXN0IGJlIGxlc3MgdGhhbiAxTUIuDQoNCkhvdyB0byBvYnRhaW4gQml0Y29pbnMNCiAgVGhlIGVhc2llc3Qgd2F5IHRvIGJ1eSBiaXRjb2lucyBpcyBMb2NhbEJpdGNvaW5zIHNpdGUuIA0KICBZb3UgaGF2ZSB0byByZWdpc3RlciwgY2xpY2sgJ0J1eSBiaXRjb2lucycsIGFuZCBzZWxlY3QgdGhlIHNlbGxlciBieSBwYXltZW50IG1ldGhvZC4NCiAgICBodHRwczovL2xvY2FsYml0Y29pbnMuY29tL2J1eV9iaXRjb2lucw0KICBBbHNvIHlvdSBjYW4gZmluZCBvdGhlciBwbGFjZXMgdG8gYnV5IEJpdGNvaW5zIGFuZCBiZWdpbm5lcnMgYnVpZGUgaGVyZToNCiAgICBodHRwOi8vY29pbmRlc2suY29tL2luZm9ybWF0aW9uL2hvdy1jYW4taS1idXktYml0Y29pbnMvICAgDQoNCkF0dGVudGlvbiENCiAgRG8" nocase wide ascii
            $encoding_ransomenote_8 = "ZWRpc3R2ZW5peV9kZWNvZGVyQGFvbC5jb20=" nocase wide ascii
      condition:
            4 of ($encoding_ransomenote_*)
}
      












