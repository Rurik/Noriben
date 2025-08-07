## <img src="https://raw.githubusercontent.com/Rurik/Noriben/master/images/noriben_logo.png" height=100> Noriben Malware Analysis Sandbox
![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2015.svg) ![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2023.svg)



<pre>
Contact Information:
@bbaskin on Twitter
brian _at_ thebaskins _dot_ com
</pre>


Noriben is a Python-based script that works in conjunction with Sysinternals Procmon to automatically collect, analyze, and report on runtime indicators of malware. In a nutshell, it allows you to run an applications, hit a keypress, and get a simple text report of the sample's activities.


Noriben allows you to not only run malware similar to a sandbox, but to also log system-wide events while you manually run malware in ways particular to making it run. For example, it can listen as you run an application that requires varying command line options, or user interaction. Or, to watch the system as you step through the application in a debugger.

While Noriben was designed for analysis of malware, it has also been widely used to audit normal software applications. In 2013 it was used by the Tor Project to provide a [public audit](https://research.torproject.org/techreports/tbb-forensic-analysis-2013-06-28.pdf) of the Tor Browser Bundle

Below is a video of debugging a VM-checking malware in a way to still get sandbox results (mis-clicks due to a mouse pointer that was 5 pixels off :))

[![Noriben running against malware checking for VM ](https://img.youtube.com/vi/kmCzAmqMeTY/0.jpg)](https://www.youtube.com/watch?v=kmCzAmqMeTY)


Noriben only requires Sysinternals procmon.exe (or procmon64.exe) to operate. It requires no pre-filtering (though it would greatly help) as it contains numerous white list items to reduce unwanted noise from system activity.


For a more detailed explanation, see <a href="http://www.slideshare.net/bbaskin/bh15-arsenal-noriben">my slide deck</a> from Black Hat 2015 Arsenal. And a more detailed blog post:
http://ghettoforensics.blogspot.com/2013/04/noriben-your-personal-portable-malware.html


I've also included a much desired frontend operator, NoribenSandbox.py. This script allows you to automate the execution of Noriben within a guest VM and retrieve the reports. It currently runs on OSX (but will be ported) and is responsible for: spinning up a predefined VM and snapshot, copying the malware to the VM, starting Noriben and the malware, waiting a predetermined period of time, copying the results to the host as a ZIP, and taking a screen capture of the VM. You can even use --update to automatically copy the newest Noriben from your host, so that you don't have to continually make new snapshots when you make a change to the script.

Want to see that in action?

[![Noriben Automation Script in Action](https://img.youtube.com/vi/GSSCM0kUqo8/0.jpg)](https://www.youtube.com/watch?v=GSSCM0kUqo8)



# Cool Features

If you have a folder of YARA signature files, you can specify it with the --yara option. Every new file create will be scanned against these signatures with the results displayed in the output results.

If you have a VirusTotal API, place it into a file named "virustotal.api" (or embed directly in the script) to auto-submit MD5 file hashes to VT to get the number of viral results.  

You can add lists of MD5s to auto-ignore (such as all of your system files). Use md5deep and throw them into a text file, use --hash <file> to read them. This will ultimately go under changes, though.

You can automate the script for sandbox-usage. Using -t <seconds> to automate execution time, and --cmd "path\exe" to specify a malware file, you can automatically run malware, copy the results off, and then revert to run a new sample.

The --generalize feature will automatically substitute absolute paths with Windows environment paths for better IOC development. For example, C:\Users\malware_user\AppData\Roaming\malware.exe will be automatically resolved to %AppData%\malware.exe.


Usage:
<pre>
--===[ Noriben v1.7.2
--===[ @bbaskin
usage: Noriben.py [-h] [-c CSV] [-p PML] [-f FILTER] [--hash HASH]
                  [--hashtype {MD5,SHA1,SHA256}] [--headless] [-t TIMEOUT]
                  [--output OUTPUT] [--yara YARA] [--generalize] [--cmd CMD]
                  [-d]

optional arguments:
  -h, --help            show this help message and exit
  -c CSV, --csv CSV     Re-analyze an existing Noriben CSV file
  -p PML, --pml PML     Re-analyze an existing Noriben PML file
  -f FILTER, --filter FILTER
                        Specify alternate Procmon Filter PMC
  --hash HASH           Specify hash whitelist file
  --hashtype {MD5,SHA1,SHA256}
                        Specify hash type
  --headless            Do not open results on VM after processing
  -t TIMEOUT, --timeout TIMEOUT
                        Number of seconds to collect activity
  --output OUTPUT       Folder to store output files
  --yara YARA           Folder containing YARA rules
  --generalize          Generalize file paths to their environment variables.
                        Default: True
  --cmd CMD             Command line to execute (in quotes)
  -d, --debug           Enable debugging
</pre>

## Notable contributors

Brian Baskin
<Your name here>
<Documentation writers welcome!>

<a href="https://twitter.com/noticemecowpie">Cowpy for the logo design</a>

## Copyright and license

Copyright 2015 Brian Baskin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this work except in compliance with the License.
You may obtain a copy of the License in the LICENSE file, or at:

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
