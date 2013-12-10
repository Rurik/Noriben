## Noriben Malware Analysis Sandbox

Like it? Buy me a beer! :) <a href='https://pledgie.com/campaigns/22876'><img alt='Click here to lend your support to: Open Source Software and make a donation at pledgie.com !' src='https://pledgie.com/campaigns/22876.png?skin_name=chrome' border='0' ></a>

Noriben is a Python-based script that works in conjunction with Sysinternals Procmon to automatically collect, analyze, and report on runtime indicators of malware. In a nutshell, it allows you to run your malware, hit a keypress, and get a simple text report of the sample's activities.





Noriben allows you to not only run malware similar to a sandbox, but to also log system-wide events while you manually run malware in ways particular to making it run. For example, it can listen as you run malware that requires varying command line options. Or, watch the system as you step through malware in a debugger.





Noriben only requires Sysinternals procmon.exe to operate. It requires no pre-filtering (though it may help) as it contains numerous black list items to reduce unwanted noise from system activity (particular to Windows XP).





Usage:
<pre>
--===[ Noriben v1.4 ]===--
--===[   @bbaskin   ]===--

usage: Noriben.py [-h] [-c CSV] [-p PML] [-f FILTER] [-t TIMEOUT]
                  [--output OUTPUT] [--generalize] [--cmd CMD] [-d]

optional arguments:
  -h, --help            show this help message and exit
  -c CSV, --csv CSV     Re-analyze an existing Noriben CSV file [input file]
  -p PML, --pml PML     Re-analyze an existing Noriben PML file [input file]
  -f FILTER, --filter FILTER
                        Specify alternate Procmon Filter PMC [input file]
  -t TIMEOUT, --timeout TIMEOUT
                        Number of seconds to collect activity
  --output OUTPUT       Folder to store output files
  --generalize          Generalize file paths to their environment variables.
                        Default: False
  --cmd CMD             Command line to execute (in quotes)
  -d                    Enable debug tracebacks
</pre>

## Errors?
One common error that appears is due to how Python 2.7 handles Ctrl-C calls during a sleep. This is seen in operation as soon as Ctrl-C is pressed with the following errors:

<pre>
[*] Launching Procmon ...
Traceback (most recent call last):
  File "Noriben.py", line 1063, in <module>
    main()
  File "Noriben.py", line 1043, in main
    live_capture()
  File "Noriben.py", line 858, in live_capture
    launch_procmon_capture()
  File "Noriben.py", line 564, in launch_procmon_capture
    sleep(3)
KeyboardInterrupt
</pre>

This is an odd error that occurs seemingly randomly, and in ways that cannot be managed.
Resolving this can be done multiple ways. Once this error occurs, you can terminate Procmon manually with 'procmon.exe /Terminate'. From this point, your Noriben*.PML file still exists and the operation can be resumed with: 'Noriben.py -p <filename>.PML'. 


Resolutions:
<pre>
1. Use Python 3.X instead of 2.X.
2. Specify a timeout period instead of using Ctrl-C.
</pre>

# Sample text report output:

<pre>
Processes Created:
==================
[CreateProcess] Explorer.EXE:1432 > "%UserProfile%\Desktop\hehda.exe"	[Child PID: 2520]
[CreateProcess] hehda.exe:2520 > "%WinDir%\system32\cmd.exe"	[Child PID: 3444]

File Activity:
==================
[New Folder] hehda.exe:2520 > C:\RECYCLER\S-1-5-21-861567501-412668190-725345543-500\$fab110457830839344b58457ddd1f357
[New Folder] hehda.exe:2520 > C:\RECYCLER\S-1-5-21-861567501-412668190-725345543-500\$fab110457830839344b58457ddd1f357\L
[New Folder] hehda.exe:2520 > C:\RECYCLER\S-1-5-21-861567501-412668190-725345543-500\$fab110457830839344b58457ddd1f357\U
[CreateFile] hehda.exe:2520 > C:\RECYCLER\S-1-5-21-861567501-412668190-725345543-500\$fab110457830839344b58457ddd1f357\@	[MD5: 814c3536c2aab13763ac0beb7847a71f]
[CreateFile] hehda.exe:2520 > C:\RECYCLER\S-1-5-21-861567501-412668190-725345543-500\$fab110457830839344b58457ddd1f357\n	[MD5: cfaddbb43ba973f8d15d7d2e50c63476]
[New Folder] hehda.exe:2520 > C:\RECYCLER\S-1-5-18
[New Folder] hehda.exe:2520 > C:\RECYCLER\S-1-5-18\$fab110457830839344b58457ddd1f357
[New Folder] hehda.exe:2520 > C:\RECYCLER\S-1-5-18\$fab110457830839344b58457ddd1f357\L
[New Folder] hehda.exe:2520 > C:\RECYCLER\S-1-5-18\$fab110457830839344b58457ddd1f357\U
[CreateFile] hehda.exe:2520 > C:\RECYCLER\S-1-5-18\$fab110457830839344b58457ddd1f357\@	[MD5: d1993f38046a68cc78a20560e8de9ad8]
[CreateFile] hehda.exe:2520 > C:\RECYCLER\S-1-5-18\$fab110457830839344b58457ddd1f357\n	[MD5: cfaddbb43ba973f8d15d7d2e50c63476]
[CreateFile] services.exe:680 > C:\RECYCLER\S-1-5-18\$fab110457830839344b58457ddd1f357\@	[MD5: d1993f38046a68cc78a20560e8de9ad8]
[New Folder] services.exe:680 > C:\RECYCLER\S-1-5-18\$fab110457830839344b58457ddd1f357\U
[CreateFile] hehda.exe:2520 > %UserProfile%\Desktop\hehda.exe	[File no longer exists]
[DeleteFile] cmd.exe:3444 > %UserProfile%\Desktop\hehda.exe

Registry Activity:
==================
[CreateKey] hehda.exe:2520 > HKLM\SOFTWARE\Microsoft\Cryptography\RNG
[CreateKey] hehda.exe:2520 > HKCU\Software\Classes\clsid
[CreateKey] hehda.exe:2520 > HKCU\Software\Classes\CLSID\{fbeb8a05-beee-4442-804e-409d6c4515e9}
[CreateKey] hehda.exe:2520 > HKCU\Software\Classes\CLSID\{fbeb8a05-beee-4442-804e-409d6c4515e9}\InprocServer32
[SetValue] hehda.exe:2520 > HKCU\Software\Classes\CLSID\{fbeb8a05-beee-4442-804e-409d6c4515e9}\InprocServer32\ThreadingModel  =  Both
[SetValue] hehda.exe:2520 > HKCU\Software\Classes\CLSID\{fbeb8a05-beee-4442-804e-409d6c4515e9}\InprocServer32\(Default)  =  C:\RECYCLER\S-1-5-21-861567501-412668190-725345543-500\$fab110457830839344b58457ddd1f357\n.
[SetValue] svchost.exe:1032 > HKLM\System\CurrentControlSet\Services\SharedAccess\Epoch\Epoch  =  404
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\Type  =  32
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\Start  =  4
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\ErrorControl  =  0
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\DeleteFlag  =  1
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\Start  =  4
[CreateKey] services.exe:680 > HKLM\System\CurrentControlSet\Control\Class\{8ECC055D-047F-11D1-A537-0000F8753ED1}\0000
[CreateKey] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\Enum
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\Enum\Count  =  0
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\SharedAccess\Enum\NextInstance  =  0
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\wscsvc\Type  =  32
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\wscsvc\Start  =  4
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\wscsvc\ErrorControl  =  0
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\wscsvc\DeleteFlag  =  1
[SetValue] services.exe:680 > HKLM\System\CurrentControlSet\Services\wscsvc\Start  =  4

Network Traffic:
==================
[UDP] hehda.exe:2520 > google-public-dns-a.google.com:53
[UDP] google-public-dns-a.google.com:53 > hehda.exe:2520
[HTTP] hehda.exe:2520 > 50.22.196.70-static.reverse.softlayer.com:80
[TCP] 50.22.196.70-static.reverse.softlayer.com:80 > hehda.exe:2520
[UDP] hehda.exe:2520 > 83.133.123.20:53
[UDP] svchost.exe:1032 > 239.255.255.250:1900
[UDP] services.exe:680 > 206.254.253.254:16471
[UDP] services.exe:680 > 190.254.253.254:16471
[UDP] services.exe:680 > 182.254.253.254:16471
[UDP] services.exe:680 > 180.254.253.254:16471
[UDP] services.exe:680 > 135.254.253.254:16471
[UDP] services.exe:680 > 134.254.253.254:16471
[UDP] services.exe:680 > 117.254.253.254:16471
[UDP] services.exe:680 > 115.254.253.254:16471
[UDP] services.exe:680 > 92.254.253.254:16471
[UDP] services.exe:680 > 88.254.253.254.dynamic.ttnet.com.tr:16471
[UDP] services.exe:680 > 254.253.254.87.dynamic.monaco.mc:16471

Unique Hosts:
==================
115.254.253.254
117.254.253.254
134.254.253.254
135.254.253.254
180.254.253.254
182.254.253.254
190.254.253.254
206.254.253.254
239.255.255.250
254.253.254.87.dynamic.monaco.mc
255.255.255.255
50.22.196.70-static.reverse.softlayer.com
83.133.123.20
88.254.253.254.dynamic.ttnet.com.tr
92.254.253.254
google-public-dns-a.google.com
</pre>


For additional information, see this blog post:
http://ghettoforensics.blogspot.com/2013/04/noriben-your-personal-portable-malware.html


## Copyright and license

Copyright 2013 Brian Baskin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this work except in compliance with the License.
You may obtain a copy of the License in the LICENSE file, or at:

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
