import "pe"

rule detect

{

meta:

desc = "CMD"

weight = 5

strings:

$2caf = "WWWWWPj"
$3278 = "OpenSCManagerA"
$08be = ";22dV::tN"
$8728 = "_local_unwind2"
$ed34 = "2+( VPOL"
$d631 = "GlobalAlloc"
$edef = "VirtualProtect"
$ef39 = "@Pbmx~P"
$1d88 = "FreeLibrary"
$adec = "^Fr`+:&"
$84a7 = "VirtualAlloc"
$3fad = "CreateDirectoryW"
$35a7 = ">k_I[$"
$07c8 = "msg/m_english.wnryF"
$8e89 = "StartServiceA"
$65f3 = ":*>B=Ox"
$25a5 = "OpenMutexA"
$5305 = "GetFullPathNameA"
$6106 = "RegSetValueExA"
$7e4e = "msg/m_french.wnry"
$c480 = "DeleteFileW"
$7354 = "QeTbF~ZiKw"
$8004 = "SbE\\lHtQeF"
$d4a8 = "Q~TbFwZiK"
$37ff = "CreateFileW"
$dc16 = ".?AVtype_info@@"
$8cb8 = "CryptDecrypt"
$e2b0 = "=j&&LZ66lA??~"
$b8d3 = "F~TbKwZi"
$059e = "incorrect data check"
$b951 = "tasksche.exe"
$66b4 = "MoveFileW"
$91b8 = "unknown compression method"
$787c = "??1exception@@UAE@XZ"
$b100 = "realloc"
$cf0e = "SetCurrentDirectoryA"
$1250 = "WriteFile"
$608f = "b4(X2;ey"
$ed8a = "__p__commode"
$e027 = "MultiByteToWideChar"
$2caa = "LoadLibraryA"
$2a49 = "\\6tGuzF"
$e922 = "%%Jo..\\r"
$6ae7 = "4$8,9-6'.6$:#?*1hHpXeA~SrZlN"
$9236 = "PPxD<<%"
$feb8 = "kernel32.dll"
$9b8d = "&%^W6)."
$1cb5 = "CryptImportKey"
$268a = "HeapFree"
$362b = "_except_handler3"
$4139 = "WaitForSingleObject"
$cbb1 = "V,YYG;~"
$06dd = "Ud|JZ|BE"
$83df = "_CxxThrowException"
$c888 = "data error"
$ba20 = "??0exception@@QAE@ABQBD@Z"
$0ef8 = "_acmdln"
$7181 = "OLEAUT32.dll"
$0d17 = ";u>H4q7.c"
$d3e8 = "GetModuleHandleA"
$abd2 = "incomplete literal/length tree"
$1ae1 = "OpenServiceA"
$6a40 = "CryptReleaseContext"
$9ab9 = "attrib +h ."
$0c76 = "inflate 1.1.3 Copyright 1995-1998 Mark Adler"
$f55a = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"
$09ec = "insufficient memory"
$3217 = "$`GnP+%<g"
$b757 = "TaskStart"
$4a8d = "msg/m_chinese (traditional).wnry"
$096e = "[_:L	x86"
$d39a = "ReadFile"
$2f00 = "Bb..fO3"
$aae4 = "qDj$bIU"
$8581 = "k|_^][Y"
$9f3d = "invalid distance code"
$795c = "wcsrchr"
$99a1 = "GetFileSizeEx"
$8e57 = "L)b7=a`"
$4eb0 = "__CxxFrameHandler"
$d7c5 = "_stricmp"
$390b = "[4+G[Tnr"
$738b = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"
$78f8 = "msg/m_croatian.wnry"
$fb21 = "CMnQ,OOr"
$7423 = "swprintf"
$ebd8 = "SetFileAttributesW"
$824c = "msg/m_czech.wnryn"
$8ad2 = "O|x8+^_"
$184a = "HeapAlloc"
$41ab = "__setusermatherr"
$2f99 = "GetWindowsDirectoryW"
$2966 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn"
$c6a8 = "LocalFileTimeToFileTime"
$ebf8 = "3/Vq9	="
$bb85 = "CryptAcquireContextA"
$3320 = "Jo7eQX%"
$5749 = "FindResourceA"
$cff2 = "'B;1?5s"
$7ac1 = "IsBadReadPtr"
$68dd = "GetExitCodeProcess"
$186e = "`.rdata"
$865c = "#`?@/9P"
$3570 = "GetTempPathW"
$c0ca = "invalid bit length repeat"
$48d1 = "MSVCRT.dll"
$45e5 = "o%%Jr..\\$"
$572c = "Global\\MsWinZonesCacheCounterMutexA"
$57d4 = "!`7RNkv"
$9774 = "__p___argc"
$5548 = "SetCurrentDirectoryW"
$a3c2 = "oversubscribed literal/length tree"
$a0e3 = "[l~y2U="
$463e = "msg/m_greek.wnry4n"
$cda8 = "invalid block type"
$2faf = "<` Xu9g"
$f115 = "GetNativeSystemInfo"
$961a = "CloseServiceHandle"
$f70e = "incomplete distance tree"
$2cc9 = "S	Q+c@x"
$762b = "8d62ro/"
$8d98 = "e	];F[p"
$54d5 = "$@^ Y+kCM3"
$3cf1 = "X(N.K&9"
$55f8 = "LeaveCriticalSection"
$0e52 = "msg/m_bulgarian.wnry"
$9c86 = "B~WJLuC"
$6508 = "invalid window size"
$f24a = "msg/m_dutch.wnry9"
$52c1 = "GetCurrentDirectoryA"
$f05c = "Hy}V2l0e"
$4806 = "xxJo%%\\r..8$"
$e55d = "NLc>zQy"
$a0aa = "=iF-s4\"t"
$b525 = "GetFileAttributesA"
$af8d = "_initterm"
$ade2 = "2{0ONU	T8"
$83e3 = "M{_rKG	C"
$19de = "4XI\"whG"
$2a0c = "DeleteCriticalSection"
$c860 = "b.wnryP8"
$735a = "GetFileSize"
$5882 = "GetFileAttributesW"
$a28b = "md)(:--"
$3d7f = "WNcry@2ol7"
$d45d = "empty distance tree with lengths"
$70df = "SizeofResource"
$0a23 = "CopyFileA"
$700a = "uo\"usd/"
$d20c = "ciC [/K"
$cbeb = "$0vJ<T9"
$bd4a = "icacls . /grant Everyone:F /T /C /Q"
$8c23 = "CryptDestroyKey"
$f2af = "oversubscribed distance tree"
$5495 = "MoveFileExW"
$2706 = "KfmZ@9q"
$6bd3 = "TerminateProcess"
$ec15 = "stream end"
$6a25 = "c.wnry%"
$6de4 = "vi#<!d*S"
$58bc = "pfgGL`R"
$fa36 = "_XcptFilter"
$eacb = "RegCreateKeyW"
$e01c = "[wS#C^6"
$c11c = "file error"
$4d67 = ">nuGl=Cme4"
$e403 = "Microsoft Enhanced RSA and AES Cryptographic Provider"
$88de = "msg/m_filipino.wnry"
$a3b6 = "incomplete dynamic bit lengths tree"
$8d00 = ".?AVexception@@"
$42d1 = "b=htZo&f"
$c305 = "KERNEL32.dll"
$7c2a = "msg/m_chinese (simplified).wnryR9"
$680a = "&&Lj66lZ??~A"
$8e0b = "#E.(`MW"
$2a20 = "cmd.exe /c \"%s\""
$8c9c = "j_1lTo`"
$d385 = "stream error"
$b9aa = "&Lj&6lZ6?~A?"
$5bbd = "WS2_32.dll"
$5d4f = "SystemTimeToFileTime"
$a224 = "- unzip 0.15 Copyright 1998 Gilles Vollant"
$95a6 = "??0exception@@QAE@ABV0@@Z"
$8896 = ",4$8'9-6:.6$1#?*XhHpSeA~NrZlE"
$7421 = "CloseHandle"
$ff6a = "??2@YAPAXI@Z"
$73df = "SetFileTime"
$74fe = "|~}%.15"
$e9e3 = "GetProcessHeap"
$5443 = "SE{^QC4"
$9a0e = "Df\"\"T~**;"
$f8f8 = "wsprintfA"
$95eb = "GetModuleFileNameA"
$5995 = "RegQueryValueExA"
$ab6d = "2/O-_.X8w.+"
$ae78 = "s<,kX5k"
$8b99 = "4I_,eJi"
$ece4 = "CreateServiceA"
$c9d4 = "f\"\"D~**T"
$57c8 = "_controlfp"
$71cc = "incompatible version"
$f5bd = "dV22tN::"
$27f6 = "_-TPsPUv: V"
$278a = "IyEf [%"
$6f8e = "__set_app_type"
$9500 = "InitializeCriticalSection"
$5b79 = "Hjz%3(0"
$3b43 = ".Vy_Fdk"
$09f7 = "'Oh'-o]"
$5a97 = "qr=_os*"
$72cd = ",MF3j;2@"
$8ba7 = "need dictionary"
$ab84 = "CreateDirectoryA"
$f491 = "pq\"b\"V1"
$79cf = "=XnFQ-Il"
$ac9e = "x%Jo%.\\r."
$d271 = "GetProcAddress"
$ae35 = "CryptEncrypt"
$a47b = "MSVCP60.dll"
$2f18 = "6P>YK^$r"
$4ae6 = "__p___argv"
$0d08 = "sprintf"
$303e = "MF2E0UG"
$b405 = "KPeJr}F"
$c3c1 = "CryptGenKey"
$08cd = "__getmainargs"
$e6a5 = "`1^9tdb"
$bf91 = "mK~}k=P"
$9442 = "ADVAPI32.dll"
$5ff1 = "GetComputerNameW"
$d913 = "!This program cannot be run in DOS mode."
$17eb = "WANACRY!"
$a792 = "incorrect header check"
$73bb = "_mbsstr"
$04d9 = "Le\"zE^f1"
$416a = "msg/m_german.wnry"
$48a8 = ""Df"*T~*"
$1691 = "SHELL32.dll"
$bffb = "8,4$6'9-$:.6*1#?pXhH~SeAlNrZbE"
$ce5f = "LockResource"
$f564 = "#cMe&(;[Ip"
$d5a9 = "advapi32.dll"
$d9cc = "Lj&&lZ66~A??"
$2976 = "L3koq_ >"
$0016 = "??1type_info@@UAE@XZ"
$f577 = "msg/m_danish.wnry"
$28ae = "^Md]"lN"
$722c = "EGBkV6"rnL9"
$510b = "?-3t/''"
$c107 = "GetStartupInfoA"
$09d2 = "tJ9@0O("
$7182 = "!A$U>=+"
$76d3 = "2dV2:tN:"
$d582 = "tlHt Ht"
$227f = "9d|!]`["
$0905 = "GlobalFree"
$d98b = "V22dN::t"
$bf02 = "nyMZ?%g;"
$8543 = "QeFbF~TiKwZ"
$0e55 = "[d+?8d["
$2feb = "EnterCriticalSection"
$51da = "LoadResource"
$ab77 = "msg/m_finnish.wnry~"
$1a76 = """Df**T~"
$f90f = "kEs##Q^!"
$cceb = "r;#r7iS|1"
$ff66 = "s]R",XC("
$59fa = "CreateFileA"
$240c = "??3@YAXPAX@Z"
$f86d = "VirtualFree"
$0c0b = "CreateProcessA"
$8b75 = "invalid literal/length code"
$e770 = "oversubscribed dynamic bit lengths tree"
$8c9e = "E65etRI\v4"
$3ef8 = "SetLastError"
$dac1 = "*4q4[`V"
$f16b = "+[\_JQ}"
$af1a = ""t=.|Vbq-"
$fd55 = "invalid stored block lengths"
$bcbf = ":95e`Il"
$b67e = "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE"
$d402 = "=1azT)8^y"
$a542 = "__p__fmode"
$75bf = "buffer error"
$bca6 = "^Ml,L;0"
$ea0e = "!#pHA[P"
$1ba0 = "*@~CS%1"
$ff3f = "~|c<caKm2"
$75fc = "C77nYmm"
$22a0 = "_adjust_fdiv"
$2186 = "7#z y,:"
$ddae = "e".E~^G"
$2abc = "pp|B>>q"
$c83d = "SetFilePointer"
$7cca = "RegCloseKey"
$5357 = "strrchr"
$5943 = "USER32.dll"
$a83e = "too many length or distance symbols"

condition:

pe.characteristics and $2caf and 
$3278 and 
$08be and 
$8728 and 
$ed34 and 
$d631 and 
$edef and 
$ef39 and 
$1d88 and 
$adec and 
$84a7 and 
$3fad and 
$35a7 and 
$07c8 and 
$8e89 and 
$65f3 and 
$25a5 and 
$5305 and 
$6106 and 
$7e4e and 
$c480 and 
$7354 and 
$8004 and 
$d4a8 and 
$37ff and 
$dc16 and 
$8cb8 and 
$e2b0 and 
$b8d3 and 
$059e and 
$b951 and 
$66b4 and 
$91b8 and 
$787c and 
$b100 and 
$cf0e and 
$1250 and 
$608f and 
$ed8a and 
$e027 and 
$2caa and 
$2a49 and 
$e922 and 
$6ae7 and 
$9236 and 
$feb8 and 
$9b8d and 
$1cb5 and 
$268a and 
$362b and 
$4139 and 
$cbb1 and 
$06dd and 
$83df and 
$c888 and 
$ba20 and 
$0ef8 and 
$7181 and 
$0d17 and 
$d3e8 and 
$abd2 and 
$1ae1 and 
$6a40 and 
$9ab9 and 
$0c76 and 
$f55a and 
$09ec and 
$3217 and 
$b757 and 
$4a8d and 
$096e and 
$d39a and 
$2f00 and 
$aae4 and 
$8581 and 
$9f3d and 
$795c and 
$99a1 and 
$8e57 and 
$4eb0 and 
$d7c5 and 
$390b and 
$738b and 
$78f8 and 
$fb21 and 
$7423 and 
$ebd8 and 
$824c and 
$8ad2 and 
$184a and 
$41ab and 
$2f99 and 
$2966 and 
$c6a8 and 
$ebf8 and 
$bb85 and 
$3320 and 
$5749 and 
$cff2 and 
$7ac1 and 
$68dd and 
$186e and 
$865c and 
$3570 and 
$c0ca and 
$48d1 and 
$45e5 and 
$572c and 
$57d4 and 
$9774 and 
$5548 and 
$a3c2 and 
$a0e3 and 
$463e and 
$cda8 and 
$2faf and 
$f115 and 
$961a and 
$f70e and 
$2cc9 and 
$762b and 
$8d98 and 
$54d5 and 
$3cf1 and 
$55f8 and 
$0e52 and 
$9c86 and 
$6508 and 
$f24a and 
$52c1 and 
$f05c and 
$4806 and 
$e55d and 
$a0aa and 
$b525 and 
$af8d and 
$ade2 and 
$83e3 and 
$19de and 
$2a0c and 
$c860 and 
$735a and 
$5882 and 
$a28b and 
$3d7f and 
$d45d and 
$70df and 
$0a23 and 
$700a and 
$d20c and 
$cbeb and 
$bd4a and 
$8c23 and 
$f2af and 
$5495 and 
$2706 and 
$6bd3 and 
$ec15 and 
$6a25 and 
$6de4 and 
$58bc and 
$fa36 and 
$eacb and 
$e01c and 
$c11c and 
$4d67 and 
$e403 and 
$88de and 
$a3b6 and 
$8d00 and 
$42d1 and 
$c305 and 
$7c2a and 
$680a and 
$8e0b and 
$2a20 and 
$8c9c and 
$d385 and 
$b9aa and 
$5bbd and 
$5d4f and 
$a224 and 
$95a6 and 
$8896 and 
$7421 and 
$ff6a and 
$73df and 
$74fe and 
$e9e3 and 
$5443 and 
$9a0e and 
$f8f8 and 
$95eb and 
$5995 and 
$ab6d and 
$ae78 and 
$8b99 and 
$ece4 and 
$c9d4 and 
$57c8 and 
$71cc and 
$f5bd and 
$27f6 and 
$278a and 
$6f8e and 
$9500 and 
$5b79 and 
$3b43 and 
$09f7 and 
$5a97 and 
$72cd and 
$8ba7 and 
$ab84 and 
$f491 and 
$79cf and 
$ac9e and 
$d271 and 
$ae35 and 
$a47b and 
$2f18 and 
$4ae6 and 
$0d08 and 
$303e and 
$b405 and 
$c3c1 and 
$08cd and 
$e6a5 and 
$bf91 and 
$9442 and 
$5ff1 and 
$d913 and 
$17eb and 
$a792 and 
$73bb and 
$04d9 and 
$416a and 
$48a8 and 
$1691 and 
$bffb and 
$ce5f and 
$f564 and 
$d5a9 and 
$d9cc and 
$2976 and 
$0016 and 
$f577 and 
$28ae and 
$722c and 
$510b and 
$c107 and 
$09d2 and 
$7182 and 
$76d3 and 
$d582 and 
$227f and 
$0905 and 
$d98b and 
$bf02 and 
$8543 and 
$0e55 and 
$2feb and 
$51da and 
$ab77 and 
$1a76 and 
$f90f and 
$cceb and 
$ff66 and 
$59fa and 
$240c and 
$f86d and 
$0c0b and 
$8b75 and 
$e770 and 
$8c9e and 
$3ef8 and 
$dac1 and 
$f16b and 
$af1a and 
$fd55 and 
$bcbf and 
$b67e and 
$d402 and 
$a542 and 
$75bf and 
$bca6 and 
$ea0e and 
$1ba0 and 
$ff3f and 
$75fc and 
$22a0 and 
$2186 and 
$ddae and 
$2abc and 
$c83d and 
$7cca and 
$5357 and 
$5943 and 
$a83e

}