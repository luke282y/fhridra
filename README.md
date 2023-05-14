# fhridra <img src=https://frida.re/img/logotype.svg width=100 height=20/> + <img src=https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Features/Base/src/main/resources/images/GHIDRA_3.png width=100 height=20 />
Python helper classes for Frida integration with Ghidra. Connect to a remote frida server from Ghidra python3 intance over TCP/IP. Allows Ghidra on host workstation to use frida and access target process/memory on target workstation. Utilizes [frida python bindings](https://github.com/frida/frida-python) and [Ghidra AP](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html)).

# Requirements
- ## Host 1 (Analysis Workstation)
  - Ghidra > 10.2 -> https://ghidra-sre.org/ 
  - Ghidrathon  -> https://github.com/mandiant/Ghidrathon
  - Frida -> https://frida.re/

- ## Host 2 (Target Workstation with Process to Debug)
  - Frida server that matches version of frida client
    - https://github.com/frida/frida/releases
    - Example: [frida-server-16.0.19-windows-x86_64.exe.xz](https://github.com/frida/frida/releases/download/16.0.19/frida-server-16.0.19-windows-x86_64.exe.xz)

# Install
Installing Ghidra,Frida, and Ghidrathon on host, then place the script FridaConnector.py in the Ghidra scripts directory. The default in windows is %USERPROFILE%\ghidra_scripts\.  

Make sure that the target host firewall is off or allows the frida server port 27042

# Usage
In the Ghidrathon console/interpreter
``` python
from FridaConnect import Connector,fridaPointer

#create new instance connected to notepad.exe process on host at 192.168.122.191
fc = Connector("192.168.122.191","notepad.exe","C:\\frida\\scripts")

#rebase the currently loaded image in Ghidra to the base image address retrieved from notepad.exe in target process
fc.rebase()
```

``` python
#execute raw frida javascript code in target process
expression = r"Process"
fc.eval(expression)
expression = r"Module.enumerateImports('notepad.exe')"
fc.eval(expression)
```
### Example output:  
```
('object', {'arch': 'x64', 'platform': 'windows', 'pointerSize': 8, 'id': 10056, 'pageSize': 4096, 'codeSigningPolicy': 'optional'})

('object', [{'type': 'function', 'name': 'GetProcAddress', 'module': 'KERNEL32.dll', 'address': '0x7ffb76e2b630'}, {'type': 'function', 'name': 'CreateMutexExW', 'module': 'KERNEL32.dll', 'address': '0x7ffb76e350f0'}, {'type': 'function', 'name': 'AcquireSRWLockShared', 'module': 'KERNEL32.dll', 'address': '0x7ffb78ab1760'}, {'type': 'function', 'name': 'DeleteCriticalSection', 'module': 'KERNEL32.dll', 'address': '0x7ffb78aa0fc0'}, .....
```

``` python
#create a frida pointer obj at current address from Ghidra listing
fp = fc.curAddr()
fp.readCString()
```
### Example output:  
```
'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<!-- Copyright (c) Microsoft Corporation -->\r\n<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\r\n<assemblyIdentity\r\n    name="Microsoft.Windows.Shell.notepad"\r\n    processorArchitecture="amd64"\r\n    version="5.1.0.0"\r\n    type="win32"/>\r\n<description>Windows Shell</description>\r\n<dependency>\r\n    <dependentAssembly>\r\n        <assemblyIdentity\r\n            type="win32"\r\n            name="Microsoft.Windows.Common-Controls"\r\n            version="6.0.0.0"\r\n            processorArchitecture="*"\r\n            publicKeyToken="6595b64144ccf1df"\r\n            language="*"\r\n        />\r\n    </dependentAssembly>\r\n</dependency>\r\n<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">\r\n    <security>\r\n        <requestedPrivileges>\r\n            <requestedExecutionLevel level="asInvoker" uiAccess="false"/>\r\n        </requestedPrivileges>\r\n    </security>\r\n</trustInfo>\r\n<application xmlns="urn:schemas-microsoft-com:asm.v3">\r\n    <windowsSettings xmlns:ws2="http://schemas.microsoft.com/SMI/2016/WindowsSettings">\r\n        <ws2:dpiAwareness>PerMonitorV2</ws2:dpiAwareness>\r\n    </windowsSettings>\r\n</application>\r\n</assembly>\r\n'
```

``` python
#create a frida Inteceptor hook at current address, hook will print first four arguments,
#registers, and stack trace
fp.hook()
```
### Example Output:
```
0x7ffb76e35730 notepad.exe!WriteFile
arg1: 0x8ec
arg2: 0x1bc275cac30
              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
1bc275cac30  64 61 73 66 61 64 73 66 61 64 73 66 61 64 66 64  dasfadsfadsfadfd
1bc275cac40  73 66 61 73 64 66 61 64 66 61 64 66 61 64 66 61  sfasdfadfadfadfa
1bc275cac50  64 73 66 00 00 00 00 00 c1 7f 4f 50 00 3c 00 88  dsf.......OP.<..
1bc275cac60  ec 4c 18 3d fb 7f 00 00 80 b1 7a 22 bc 01 00 00  .L.=......z"....
arg3: 0x23
arg4: 0x406c27e9f0
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
406c27e9f0  00 00 00 00 00 00 00 00 b0 c9 d1 20 bc 01 00 00  ........... ....
406c27ea00  f0 ea 27 6c 40 00 00 00 e0 20 0c 2a f6 7f 00 00  ..'l@.... .*....
406c27ea10  23 00 00 00 00 00 00 00 00 00 00 00 fb 7f 00 00  #...............
406c27ea20  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
{
  "pc": "0x7ffb763a4f00",
  "sp": "0x406c27e978",
  "rax": "0x23",
  "rcx": "0x8ec",
  "rdx": "0x1bc275cac30",
  "rbx": "0x1bc275cac30",
  "rsp": "0x406c27e978",
  "rbp": "0xfde9",
  "rsi": "0x23",
  "rdi": "0x23",
  "r8": "0x23",
  "r9": "0x406c27e9f0",
  "r10": "0x66",
  "r11": "0x1bc275cac30",
  "r12": "0x0",
  "r13": "0x8ec",
  "r14": "0x0",
  "r15": "0x1bc20d1c9b0",
  "rip": "0x7ffb763a4f00"
}
Backtrace:
0x7ff62a09e69a
0x7ff62a09ea1c
0x7ff62a098efb
0x7ff62a09aaf0
0x7ffb786ce858 notepad.exe!CallWindowProcW
0x7ffb786ce3dc notepad.exe!DispatchMessageW
0x7ffb786e0c33 notepad.exe!SendMessageTimeoutW
0x7ffb78b30eb4 notepad.exe!KiUserCallbackDispatcher
0x7ffb761a1264 notepad.exe!NtUserTranslateAccelerator
0x7ff62a09afa2
0x7ff62a0b3ec6
0x7ffb76e27604 notepad.exe!BaseThreadInitThunk
0x7ffb78ae26a1 notepad.exe!RtlUserThreadStart
```