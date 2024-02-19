from msilib.schema import Environment
import socket
from tokenize import Ignore
from turtle import clear
import pyfiglet
from datetime import datetime
import sys
import os    
import argparse

# help page
def exitPage():
    exitcommand = input("Please enter Q to exit this page\n>")
    if exitcommand.upper() == "Q":
         os.system('cls')
         Startup()
    else:
        exitPage() 
         
def helpPage():
     print ("""
            -- Help Page --
            Port Scanner will ping ports of the desired target host and display the open ports within the target host.
            - Commands -
            -      -H   ping one target host
            -      -t   ignores the targeted host
            -      -L   sends the output to a desired text file      
            -      man  Manual page for options
            """)
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
    # Asking user to enter their target host or target file
    command = input("enter target host or target file\nuse command help for options\n\n>")
    try:
        if command.lower() == "help": # convert the text from input into a lowercase and check if user has inputed help command
            helpPage() 
        else:
            print("invalid command - see help page or man page\n>")
    except:
            print("invalid command - see help page or man page\n>")    
 
Startup()

# man page

# port scanning the desired IP address

# running startup script

