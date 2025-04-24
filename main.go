package main

import (
	_ "embed"
	"flag"
	"fmt"
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

	fmt.Println("Target:", target)

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
		handleServiceSession(target, batch, username, password, domain, name, description)

	} else if method == "pipe" {
		// Enter full-interactive shell using named pipes
		handlePipeSession(target, username, password, domain, name, dropmethod)
	} else if method == "http" {
		// Enter full-interactive shell using HTTP Client/Server

	}

}

func parseArgs() (map[string]any, error) {

	target := flag.String("target", "", "Remote Hostname or IP address")
	method := flag.String("method", "wmi", "Method to use for remote execution (wmi, task, service, pipe, http)")
	batch := flag.Bool("batch", false, "If true, will copy commands to a batch file on target and execute rather than direct cmd processor - useful for long commands")

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
	runas := flag.Bool("runas", false, "If true, will run the task as the user specified in -user flag instead of SYSTEM - specified user must have Batch Job Rights")

	dropmethod := flag.String("dropmethod", "wmi", "Method to use for creating named pipe (wmi, task, service)")

	flag.Parse()

	validMethods := []string{"wmi", "task", "service", "pipe", "http"}
	if !slices.Contains(validMethods, *method) {
		return nil, fmt.Errorf("invalid method: %s", *method)
	}

	if *target == "" {
		return nil, fmt.Errorf("target is required")
	}

	if *username != "" && *password == "" {
		return nil, fmt.Errorf("password is required if username is provided")
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
	}
	return arguments, nil
}
