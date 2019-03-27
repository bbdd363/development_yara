rule test{
  meta:
	  author = "Gang seongMuk
      date = "2018-11-21"
	  filetype = "Win32 EXE
      MD5 = 40A5312F203F48759CBC1C08F91C499A
	  type = "Gryphone Ransomeware
	  description = "Rule to detect Gryphone Ransomeware"
  strings:
	  // Mutex Name
      $test_0 = "DEMONSLAY335QQ" nocase wide ascii
      $test_1 = "DEMONSLAY335QQ" nocase wide ascii
	  
	  // Shellcode content
	  $test_2 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" nocase wide ascii
      $test_3 = "/c bcdedit.exe /set {default} recoveryenabled No" nocase wide ascii
      $test_4 = "/c vssadmin.exe Delete Shadows /All /Quiet" nocase wide ascii
	  
	  //File name white list 
	  $test_3 = "gryphon" nocase wide ascii
      $test_2 = ".gryphon" nocase wide ascii
      $test_1 = "BOOTMGR" nocase wide ascii
      $test_0 = "!## DECRYPT FILES ##!.txt" nocase wide ascii
	  
	  //File route white list 
	  $test_14 = "program files (x86)" nocase wide ascii
      $test_13 = "program files" nocase wide ascii
      $test_12 = "temp" nocase wide ascii
      $test_11 = "inetpub" nocase wide ascii
      $test_10 = "appdata" nocase wide ascii
      $test_7 = "windows" nocase wide ascii
      $test_6 = "programdata\\" nocase wide ascii
      $test_5 = "programdata" nocase wide ascii
      $test_4 = "ProgramData" nocase wide ascii
      $test_3 = "msocache" nocase wide ascii
      $test_2 = "$recycle.bin" nocase wide ascii
      $test_1 = ".." nocase wide ascii
      $test_0 = "." nocase wide ascii
      $test_9 = "intel" nocase wide ascii
      $test_8 = "nvidia" nocase wide ascii
	  
	  // restore desination e-mail
      $test_0 = "ZWRpc3R2ZW5peV9kZWNvZGVyQGFvbC5jb20=" nocase wide ascii
	  $test_0 = edistveniy_decoder@aol.com
	  
	  //ransomenote Encoding string 
	  $test = "0pVSha3RdFA38b7pvn34PwtH7tgGxmauYbrg+z9tKeRCqlZ3dUj+RLn+BbwjqE6cPZnR4ziLFrrcJTdAiAV9NVTKnoVU//Wm/cozIsXP5hu+aBGnnMAWS+ViD5Sal2DS08MfGrnr6C64Zm+tZKmAYpNf+o98e4sFozfymqITlbY=" nocase wide ascii
	  $test = "DQo9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gR1JZUEhPTiBSQU5TT01XQVJFID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQ==" nocase wide ascii
	  $test = 0pVSha3RdFA38b7pvn34PwtH7tgGxmauYbrg+z9tKeRCqlZ3dUj+RLn+BbwjqE6cPZnR4ziLFrrcJTdAiAV9NVTKnoVU//Wm/cozIsXP5hu+aBGnnMAWS+ViD5Sal2DS08MfGrnr6C64Zm+tZKmAYpNf+o98e4sFozfymqITlbY=
	  $test = 0pVSha3RdFA38b7pvn34PwtH7tgGxmauYbrg+z9tKeRCqlZ3dUj+RLn+BbwjqE6cPZnR4ziLFrrcJTdA
	  $test = iAV9NVTKnoVU//Wm/cozIsXP5hu+aBGnnMAWS+ViD5Sal2DS08MfGrnr6C64Zm+tZKmAYpNf+o98e4sFozfymqITlbY=
      $test = DQo9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gR1JZUEhPTiBSQU5TT01XQVJFID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQ==
      $test = PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09IEdSWVBIT04gUkFOU09NV0FSRSA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0NCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQUxMIFlPVVIgRklMRVMgSEFWRSBCRUVOIEVOQ1JZUFRFRA0KDQpBbGwgeW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVkIGR1ZSB0byBhIHNlY3VyaXR5IHByb2JsZW0gd2l0aCB5b3VyIFBDLg0KSWYgeW91IHdhbnQgdG8gcmVzdG9yZSB0aGVtLCB3cml0ZSB1cyB0byB0aGUgZS1tYWlsOiA=
      $test = WW91IGhhdmUgdG8gcGF5IGZvciBkZWNyeXB0aW9uIGluIEJpdGNvaW5zLiBUaGUgcHJpY2UgZGVwZW5kcyBvbiBob3cgZmFzdCB5b3Ugd3JpdGUgdG8gdXMuDQpBZnRlciBwYXltZW50IHdlIHdpbGwgc2VuZCB5b3UgdGhlIGRlY3J5cHRpb24gdG9vbCB0aGF0IHdpbGwgZGVjcnlwdCBhbGwgeW91ciBmaWxlcy4NCg0KRnJlZSBkZWNyeXB0aW9uIGFzIGd1YXJhbnRlZQ0KICBCZWZvcmUgcGF5aW5nIHlvdSBjYW4gc2VuZCB0byB1cyB1cCB0byAzIGZpbGVzIGZvciBmcmVlIGRlY3J5cHRpb24uDQogIFBsZWFzZSBub3RlIHRoYXQgZmlsZXMgbXVzdCBOT1QgY29udGFpbiB2YWx1YWJsZSBpbmZvcm1hdGlvbiBhbmQgdGhlaXIgdG90YWwgc2l6ZQ0KICBtdXN0IGJlIGxlc3MgdGhhbiAxTUIuDQoNCkhvdyB0byBvYnRhaW4gQml0Y29pbnMNCiAgVGhlIGVhc2llc3Qgd2F5IHRvIGJ1eSBiaXRjb2lucyBpcyBMb2NhbEJpdGNvaW5zIHNpdGUuIA0KICBZb3UgaGF2ZSB0byByZWdpc3RlciwgY2xpY2sgJ0J1eSBiaXRjb2lucycsIGFuZCBzZWxlY3QgdGhlIHNlbGxlciBieSBwYXltZW50IG1ldGhvZC4NCiAgICBodHRwczovL2xvY2FsYml0Y29pbnMuY29tL2J1eV9iaXRjb2lucw0KICBBbHNvIHlvdSBjYW4gZmluZCBvdGhlciBwbGFjZXMgdG8gYnV5IEJpdGNvaW5zIGFuZCBiZWdpbm5lcnMgYnVpZGUgaGVyZToNCiAgICBodHRwOi8vY29pbmRlc2suY29tL2luZm9ybWF0aW9uL2hvdy1jYW4taS1idXktYml0Y29pbnMvICAgDQoNCkF0dGVudGlvbiENCiAgRG8
      $test = ZWRpc3R2ZW5peV9kZWNvZGVyQGFvbC5jb20=

	  
  condition:
      all of them
}