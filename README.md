### goexec

Remote command execution through asynchronous and interactive shells - a variety of options to replicate PsExec/PaExec style functionality depending on needs, requirements and limitations with a high level of customization.

goexec enables users to launch ad-hoc commands without full interactive shells through WMI, Scheduled Tasks and Windows Services (wip). It also provides the ability to launch interactive shells through either named pipes or TCP streams.

### Features

* Asynchronous command execution
  * WMI (wmi - default)
  * Scheduled Tasks (task)
  * Service Manager (service)
  * All of these rely on SMB to read the resulting command output - task/service names can be customized as needed - if none is specified, a random one is created and deleted following execution.
  * If a name is specified, the resulting task will not be deleted.
* Interactive command execution
  * Named Pipe (pipe)
  * TCP Server (tcp)
  * Either method can be used to achieve a fully interactive shell
  * The named pipe method is a direct SMB connection to the target machine, while TCP can be bind or reverse in nature
  * Both mechanisms require the deployment of an embedded executable onto the target via SMB

#### Usage
* **-batch**
  * If true, will copy commands to a batch file on target and execute rather than direct cmd execution - useful for long commands
* -**description** string
  * Description for the service/task - if blank, will use a default description
*  -**domain** string
  * Domain for remote authentication - should be FQDN such as domain.com or similar - if blank and user is specified will assume local user
* -**dropmethod** string
  * Method to use for creating named pipe (wmi, task, service) (default "wmi")
* -**evasion** string
  * conhost, diskshadow, ftp
* -**ip** string
  * IP to use for TCP reverse shells (default "1.1.1.1")
* -**method** string
  * Method to use for remote execution (wmi, task, service, pipe, tcp) (default "wmi")
* -**name** string
  * Service/Task/Pipe name to use for remote execution - if blank, will generate a random name
* -**pass** string
  * Password for remote authentication - necessary when using from non-domain device -> domain-joined device
* -**port** int
  * Port to use for TCP shells - must specify port if using TCP mode (default 8859)
* -**reverse**
  * If true, will create a reverse shell instead of bind shell - for TCP mode - must specify ip for connect-back
* -**runas**
  * If true, will run the task as the user specified in -user flag instead of SYSTEM assuming the user has the correct permissions - does NOT work yet for WMI which will always run as specified user
* -**shell** string
  * Shell to use for TCP shells - default is cmd.exe, valid options are (cmd, ps) (default "cmd")
* -**target** string
  * Remote Hostname or IP address to target
* -**user** string
  * Username for remote authentication - if domain user, be sure to supply -domain flag




* Credits
  * github.com/hirochachacha/go-smb2 (BSD2)
  * github.com/go-ole/go-ole (MIT)