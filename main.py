#Imports TBD
import sys, os
from ClamScanner import ClamScanner
from TraceeScanner import TraceeScanner
from TrivyScanner import TrivyScanner

print(r"""
    ____             __             ______           _____                                 
   / __ \____  _____/ /_____  _____/ ____/___ _   __/ ___/_________ _____  ____  ___  _____
  / / / / __ \/ ___/ //_/ _ \/ ___/ __/ / __ \ | / /\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /_/ / /_/ / /__/ ,< /  __/ /  / /___/ / / / |/ /___/ / /__/ /_/ / / / / / / /  __/ /    
/_____/\____/\___/_/|_|\___/_/  /_____/_/ /_/|___//____/\___/\__,_/_/ /_/_/ /_/\___/_/     

Type "help" for a list of commands.
""")

help_menu = {
             "help" : "Displays a list of valid commands.",
             "singlescan" : "Enables the user to choose a file and tool to perform a scan.",
             "envscan" : "Runs a multi-file scan on all files in /containers.",
             "exit" : "Quit the program and return to the shell.",
             "q" : "An alias for \"exit\""
            }

toolMap = {
            1 : "ClamAV",
            2 : "Trivy",
            3 : "Tracee"
          }

global_cmd = None

def user_input(isInt = False):
    #Collect a string/int input from the user and display the current active command
    out = None

    if global_cmd == None:
        out = input("\nDockerEnvScanner> ")
    else:
        out = input("\nDockerEnvScanner/{}> ".format(global_cmd))

    #Ensure int inputs are valid
    if isInt:
        properCast = False
        while not properCast:
            try:
                out = int(out)
                properCast = True
            except ValueError:
                print("Input must be an integer.")

                if global_cmd == None:
                    out = input("\nDockerEnvScanner> ")
                else:
                    out = input("\nDockerEnvScanner/{}> ".format(global_cmd))

    return out.lower() if not isInt else out

def file_input():
    print("Which file/directory would you like to scan? Enter its list number (e.g. 3).")
    
    #Print contents of /containers
    num = 1
    for filename in containers:
        print("{}. {}".format(num, filename))
        num += 1

    scanChoice = user_input(True)

    if scanChoice < 1 or scanChoice > len(containers):
        print("File/directory out of range. Exiting singlescan...")
        return None

    return scanChoice

#Main user loop
while True:
    global_cmd = None
    cmd = user_input()

    match cmd:
        case "help":
            global_cmd = "help"

            print("[COMMAND]: [DESCRIPTION]")
            for key, value in help_menu.items():
                print("{}: {}".format(key, value))
            
            continue

        case "singlescan":
            global_cmd = "singlescan"
            containers = os.listdir("./containers")

            try:
                containers[0]
            except Exception:
                print("No files found in /containers. For container analysis, please place one or more files in that directory and run singlescan again.")
                continue

            print("Which tool would you like to use?")
            print("1. ClamAV\n2. Trivy\n3. Tracee")

            toolChoice = user_input(True)

            if toolChoice < 1 or toolChoice > 3:
                print("Tool selection out of range. Exiting singlescan...")
                continue

            match toolChoice:
                case 1:
                    scanChoice = file_input()

                    if scanChoice == None:
                        continue

                    #Call ClamAV scanner
                    print("Calling tool {}".format(toolMap[toolChoice]) + (" on file/directory {}".format(containers[scanChoice - 1]) if scanChoice != None else "") + "...")
                    scanner = ClamScanner()
                    scanner.scan(False, containers[scanChoice - 1])
                    continue

                case 2:
                    print("Would you like to scan a file/directory or a Docker image?\n1. File/Directory\n2. Image")
                    trivyChoice = user_input(True)

                    match trivyChoice:
                        case 1:
                            #Scan a file with Trivy
                            scanChoice = file_input()

                            if scanChoice == None:
                                continue

                            print("Calling tool {}".format(toolMap[toolChoice]) + (" on file/directory {}".format(containers[scanChoice - 1])) + "...")
                            scanner = TrivyScanner()
                            scanner.scan(False, 0, containers[scanChoice - 1])
                            continue

                        case 2:
                            #Scan a Docker image with Trivy
                            print("Enter the name of the Docker image you'd like to scan (e.g. aquasec/trivy):")
                            image = user_input(False)
                            print("Calling tool {}".format(toolMap[toolChoice]) + (" on image {}").format(image) + "...")
                            scanner = TrivyScanner()
                            scanner.scan(False, 1, image)
                            continue

                        case _:
                            print("Selection out of range. Exiting singlescan...")
                            continue

                    continue

                case 3:
                    #Call Tracee scanner
                    scanChoice = None
                    print("Calling tool {}".format(toolMap[toolChoice]) + "...")
                    scanner = TraceeScanner()
                    scanner.scan(False)
                    continue

                case _:
                    #Default case
                    print("Tool selection out of range. Exiting singlescan...")
                    continue

            continue

        case "envscan":
            global_cmd = "envscan"
            #TODO run a novel scan of all files in /containers and report their relationships
            print("envscan not implemented.")
            continue

        case "exit":
            #Quit
            sys.exit(0)

        case "q":
            #Quit
            sys.exit(0)

        case _:
            #Default case
            print("Invalid command entered. Tip: type \"help\" for a list of valid commands.")
            continue

