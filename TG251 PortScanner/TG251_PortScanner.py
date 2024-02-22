from asyncio.windows_events import NULL
from email.headerregistry import DateHeader
from msilib.schema import File
from pickle import NONE
import socket
import textwrap
import time
from tracemalloc import start
from datetime import date, datetime
import sys
import os    
import argparse, textwrap

PortDic = [20,21,22,53,80,123,179,443,500,587,2556,3389]
FileDic = []
socket.setdefaulttimeout(0.2) #sets the default time out to be 0.2 second
# Gathers targetaddress and portaddress entered within the startup code. 
# Once gathered will use socket to connect to the target address and portaddress
# Result if ping comes back is True else False
def Portopen(TargetedAddress,PortAddress):
    s = socket.socket()
    
    try:
        s.connect((TargetedAddress,PortAddress))
    except:
        return False
    else:
        return True

def Startup():
    #  adds the date to the banner and time
    print('''
######                          #####                                            
#     #  ####  #####  #####    #     #  ####    ##   #    # #    # ###### #####  
#     # #    # #    #   #      #       #    #  #  #  ##   # ##   # #      #    # 
######  #    # #    #   #       #####  #      #    # # #  # # #  # #####  #    # 
#       #    # #####    #            # #      ###### #  # # #  # # #      #####  
#       #    # #   #    #      #     # #    # #    # #   ## #   ## #      #   #  
#        ####  #    #   #       #####   ####  #    # #    # #    # ###### #    #                                                          
          ''')

    date = datetime.now()
    dateFormat = '%d-%m-%Y %H:%M'
    dateObj = datetime.strftime(date, dateFormat)
    print(f"#### {dateObj} ####")

    try:
        # Help menu using -h - displays brief description of the item
        # Argument option being created to ensure user has the mandatory options in command
        parser = argparse.ArgumentParser(prog='PortScanner',description='## Help Page ##\n Script scans the target address for open ports',formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-p,', dest='port',type=int, help=textwrap.dedent('Accepts one port to scan\n- If left out will scan 1 - 1024\n- Put 0 to scan common ports\n\n'))
        parser.add_argument('-l,', dest='output',type=int, help=textwrap.dedent('Writes the output to text file'))
        mandatoryArgs = parser.add_argument_group('Mandatory exclusive commands')
        requiredArgs = mandatoryArgs.add_mutually_exclusive_group(required=True)
        requiredArgs.add_argument('-H,', dest='host',type=str, help='Accepts one target address\n- cannot be used with -t option\n\n')
        requiredArgs.add_argument('-t,', dest='file',type=str, help='Reads text file and pings all target address\n- cannot be used with -H option\n\n')
        args = parser.parse_args()
    
        TargetedAddress = args.host
        PortAddress = args.port
        readFileLoc = args.file
        outputFile = args.output
        beforetime = time.time()
        
        def scanning():
            # if not port range is given or no -p is given automatically goes through all ports
            # prints the if the port is open or closed and adds this to a file dictonary to be used to insert into a text file with -l
            if args.port == None:
                print("Warning Scanning all ports between 1 - 1024, this may be slow")
                print("TargetedAddress :   PortAddress\n")
                for PortAddress in range (1,1024): # max port range from 1 to 1024
                    if Portopen(TargetedAddress, PortAddress):
                        print(f"{TargetedAddress}   :   {PortAddress}   open ")
                        FileDic.append(f"{TargetedAddress}  :   {PortAddress}   open")
                    else:
                        print(f"{TargetedAddress}   :   {PortAddress}   closed")
                        FileDic.append(f"{TargetedAddress}  :   {PortAddress}   closed")
            # if port 0 is given will go through portdictonary above contains common ports
            # prints the if the port is open or closed and adds this to a file dictonary to be used to insert into a text file with -l            
            elif PortAddress == 0:
                PortDiclength = len(PortDic)
                i = 0
                print("TargetedAddress :   PortAddress\n")
                while i < PortDiclength:
                    for PortAddress in range (PortDic[i],PortDic[i]+1): # max port range from 1 to 1024
                        if Portopen(TargetedAddress, PortAddress):
                            print(f"{TargetedAddress}   :   {PortAddress}   open ")
                            FileDic.append(f"{TargetedAddress}  :   {PortAddress}   open")
                        else:
                            print(f"{TargetedAddress}   :   {PortAddress}   closed")
                            FileDic.append(f"{TargetedAddress}  :   {PortAddress}   closed")
                    i += 1
            # if port range is given will go through all ports between 1 and the given number
            # prints the if the port is open or closed and adds this to a file dictonary to be used to insert into a text file with -l        
            else:
                print("TargetedAddress :   PortAddress\n")
                for PortAddress in range (PortAddress,PortAddress+1): # grabs port given and adds 1 as exlucisve
                    if Portopen(TargetedAddress, PortAddress):
                        print(f"{TargetedAddress}   :   {PortAddress}   open ")
                        FileDic.append(f"{TargetedAddress}  :   {PortAddress}   open")
                    else:
                        print(f"{TargetedAddress}   :   {PortAddress}   closed")
                        FileDic.append(f"{TargetedAddress}  :   {PortAddress}   closed")
                
                
            # collects the beforetime and aftertime to calculate to time taken to complete
            aftertime = time.time()
            print(f'\n--Completed Port Scan--\nTime taken {aftertime-beforetime:.2f} seconds')
        ## if -t option is used will open up file and read each line and test the ports for each Target Address given
        try:
            if args.file != None:
                readFile = open(readFileLoc,'r')
                count = 0
                while True:
                    count +=1
                    line = readFile.readline()
                    TargetedAddress = line
                    scanning()
                    if not line:
                        break     
            elif args.port != None or args.port == None:
                scanning()
        except:
            print("please provide correct file location")
            
    except:
        print("No options provided, please provide option and start again\n")

Startup()