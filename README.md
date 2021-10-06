# CVP Auto Move Container

The setup.sh script will install the required python3 modules as defined in the requirements.txt document.  Please run this script first to ensure that all required modules are installed.

The devices.yml or .csv file is a list of approved devices that can be onboarded to CVP.  This list should contain the mac address of the device, the IP address, and the container that the device should belong to.   

Auto-move.py checks the Undefined container for devices and compares it to the list of approved devices in the devices.yml file.  Once it moves the devices it will check the list of tasks and run the one that is pending for the device. 

Logging is disabled by default, if you would like to enable it for any purpose please use the switch --logging with the level set to info, error, or debug (ie. --logging info).

List of available switches when running the script are below:

        * --cvp                                (IP address of Cloudvision server)
        * --username username                  (Device Username)
        * --password password                  (Device Password)
        * --logging                            (Enable logging and set the leve to info, error, or debug)
        * --devlist                            (Filename of the YAML or CSV file with the approved devices)