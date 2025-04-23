Utility for remotely executing commands with multiple executions methods:


* WMI (Psuedo-Interactive)
  * Relies on SMB to read results
  * Launches a remote process, server writes results to temporary file, client waits for file to exist and reads results
* Scheduled Tasks (Psuedo-Interactive)
  * Relies on SMB to read results
* Service Manager (Psuedo-Interactive)
  * Relies on SMB to read results if > Size limit of Service Description
* Named Pipe (Interactive)
  * SMB interactive shell
* Custom Server on ephemeral port (Interactive)
  * Deploys custom server via SMB and interacts via TCP for shell