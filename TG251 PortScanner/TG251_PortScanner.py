import socket
from tracemalloc import start
import pyfiglet
from datetime import datetime
import sys
import os    
import argparse

PortDic = ['20','21','22','80','2556']
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

def Startup():
    # creating banner for inital startup of the portscanner
    BannerText = "Port Scanner"
    AsciiBanner = pyfiglet.figlet_format(BannerText)
    print(AsciiBanner)
    try:
        # Help menu using -h - displays brief description of the item
        # Argument option being created to ensure user has the mandatory options in command
        parser = argparse.ArgumentParser(prog='PortScanner',description='Scans the target address for open ports',epilog='Text at the bottom of help')
        parser.add_argument('-p,', dest='port',type=str, help='Accepts one port to scan - if blank will scan common ports')
        requiredArguemnts = parser.add_mutually_exclusive_group(required=True)
        requiredArguemnts.add_argument('-H,', dest='host',type=str, help='Accepts one IPV4 address - cannot be used with -t option')
        requiredArguemnts.add_argument('-t,', dest='file',type=str, help='Reads text file and pings all IPV4 address - cannot be used with -H option')
        args = parser.parse_args()
    
        TargetedAddress = args.host
        PortAddress = args.port
        print(TargetedAddress)
        print(PortAddress)
    except:
        os.system('cls')
        Startup()

Startup()

# man page

# port scanning the desired IP address

# running startup script

