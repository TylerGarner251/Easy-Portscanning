from asyncio.windows_events import NULL
from pickle import NONE
import socket
import textwrap
import time
from tracemalloc import start
import pyfiglet
import datetime
import sys
import os    
import argparse, textwrap

PortDic = [20,21,22,53,80,123,179,443,500,587,2556,3389]
socket.setdefaulttimeout(0.3) #sets the default time out to be 0.3 second
# help page
def exitPage():
    exitcommand = input("Please enter Q to exit this page\n>")
    if exitcommand.upper() == "Q":
         os.system('cls')
         Startup()
    else:
        exitPage() 
def manPage():
     print("""
--- Manual Page ---
           """)

def Portopen(TargetedAddress,PortAddress):
    s = socket.socket()
    
    try:
        s.connect((TargetedAddress,PortAddress))
    except:
        return False
    else:
        return True

def Startup():
    # creating banner for inital startup of the portscanner
    BannerText = "Port Scanner"
    AsciiBanner = pyfiglet.figlet_format(BannerText)
    print(AsciiBanner)

    try:
        # Help menu using -h - displays brief description of the item
        # Argument option being created to ensure user has the mandatory options in command
        parser = argparse.ArgumentParser(prog='PortScanner',description='Scans the target address for open ports',formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-p,', dest='port',type=int, help=textwrap.dedent('Accepts one port to scan\n- If left out will scan 1 - 1024\n- Put 0 to scan common ports\n\n'))
        parser.add_argument('-l,', dest='file',type=int, help=textwrap.dedent('Writes the output to text file'))
        mandatoryArgs = parser.add_argument_group('Mandatory exclusive commands')
        requiredArgs = mandatoryArgs.add_mutually_exclusive_group(required=True)
        requiredArgs.add_argument('-H,', dest='host',type=str, help='Accepts one target address\n- cannot be used with -t option\n\n')
        requiredArgs.add_argument('-t,', dest='file',type=str, help='Reads text file and pings all target address\n- cannot be used with -H option\n\n')
        args = parser.parse_args()
    
        TargetedAddress = args.host
        PortAddress = args.port

        beforetime = time.time()

        # if not port range is given or no -p is given automatically goes through all ports 
        if args.port == None:
            print("Warning Scanning all ports between 1 - 1024, this may be slow")
            print("TargetedAddress :   PortAddress\n")
            for PortAddress in range (1,1024): # max port range from 1 to 1024
                if Portopen(TargetedAddress, PortAddress):
                    print(f"{TargetedAddress}   :   {PortAddress}   open ")
                else:
                    print(f"{TargetedAddress}   :   {PortAddress}   closed")
        # if port 0 is given will go through portdictonary above contains common ports
        elif PortAddress == 0:
            PortDiclength = len(PortDic)
            i = 0
            print("TargetedAddress :   PortAddress\n")
            while i < PortDiclength:
                for PortAddress in range (PortDic[i],PortDic[i]+1): # max port range from 1 to 1024
                    if Portopen(TargetedAddress, PortAddress):
                        print(f"{TargetedAddress}   :   {PortAddress}   open ")
                    else:
                        print(f"{TargetedAddress}   :   {PortAddress}   closed")
                i += 1
        # if port range is given will go through all ports between 1 and the given number
        else:
            print("TargetedAddress :   PortAddress\n")
            for PortAddress in range (PortAddress,PortAddress+1): # grabs port given and adds 1 as exlucisve
                if Portopen(TargetedAddress, PortAddress):
                    print(f"{TargetedAddress}   :   {PortAddress}   open ")
                else:
                    print(f"{TargetedAddress}   :   {PortAddress}   closed")
        # collects the beforetime and aftertime to calculate to time taken to complete
        aftertime = time.time()
        print(f'\n--Completed Port Scan--\nTime taken {aftertime-beforetime:.2f} seconds')
    except:
        print("No options provided, please provide option and start again\n")

Startup()

# man page

# port scanning the desired IP address

# running startup script

