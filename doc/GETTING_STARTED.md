# Basic setup

## Requirements
@todo Windows Version?

- Windows VM 
    - Windows 7 +
    - Python 3 installed. [Python Downloads for Windows](https://www.python.org/downloads/windows/). You may have better luck on a VM with the executable installer than web based. **Check the box to add Python to path**. Make note of path to python.exe if you plan to run Automated Sandbox.
    
- For automated sandbox detonation
    - Host with Python 3 installed.
    - VMWare with Windows VM above
    @todo does Noriben work with Virtual Box?
    

## Quick Start

### On the VM 
- Copy the following files to the Windows desktop
    - [SysInternals procmon.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) (get it from Microsoft)
    - Noriben.py and ProcMonConfiguration.pmc from the Noriben repo
    
    
#### Manual Detonation
1. Start Windows VM
2. Get sample onto VM using your preferred method. 
3. Double click on Noriben.py which should have Python icon if Python correctly installed
4. Wait for Noriben to finish setup
5. Initiate execution of sample
6. Allow to run as long at you want. Note: log file will grow quickly.
7. When done logging press ctrl-c
8. Report will be written to VM desktop


#### Automated Sandbox Detonation
1. Set up Windows VM as above
2. Edit NoribenSandbox.py on your host (see options below for more info on options)

#### Automated Sandbox Options

- `VMX=/full/path/to/vm/on/disk.vm`  -  If you're not sure of the path, right-click the VM in the VMware 
Browser and choose "Show in Finder/Explorer". 
- `VMRUN=vmrun_os['mac|windows']` OS of host from which you're running NoribenSandbox.py
- `VM_SNAPSHOT='Name of snapshot you want to detonate on'`
- `VM_USER='Name of VM User'`
- `VM_PASS='Password for above user'`
- `noriben_path='C:\\path\\to\\Noriben.py\\on\\VM'`
- `procmon_config_path=''C:\\path\\to\\ProcmonConfiguration.pmc\\on\\VM'` 