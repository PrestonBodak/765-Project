#Imports TBD
import sys, os
#TODO import scanner file

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

global_cmd = None
def user_input(isInt = False):
    #Collect a string/int input from the user and display the current active command
    out = None

    if global_cmd == None:
        out = input("DockerEnvScanner> ")
    else:
        out = input("DockerEnvScanner/{}> ".format(global_cmd))

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
                    out = input("DockerEnvScanner> ")
                else:
                    out = input("DockerEnvScanner/{}> ".format(global_cmd))

    return out.lower() if not isInt else out

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

            print("Which file would you like to scan? Enter its list number (e.g. 3).")

            #Print contents of /containers
            num = 1
            for filename in containers:
                print("{}. {}".format(num, filename))
                num += 1

            scanChoice = user_input(True)

            print("Which tool would you like to use to analyze {}?".format(containers[scanChoice - 1]))

            #TODO replace with true tool options
            print("1. Cool Tool\n2. Other Tool")

            toolChoice = user_input(True)

            #TODO call scanner with chosen tool
            print("TODO: calling tool on file...")

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

