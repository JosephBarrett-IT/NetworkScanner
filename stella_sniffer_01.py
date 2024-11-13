#!/bin/python
"""Stella Sniffer a Network Scanner wrote in python
    Made by Joseph Barrett November 2024"""
import subprocess
import nmap
from pyfiglet import Figlet
import crayons

def print_figlet_color(text,font='slant', color='green'):
    """ASCII Art header"""
    f = Figlet(font = font)
    print(crayons.green(f.renderText('Stella Sniffer'),color))

def scan():
    """Collects userinput and use's input for scan using nmap"""
    nm = nmap.PortScanner()
    host = input('Enter IP to scan\n')
    print('\n')
    ports = input('Enter ports to scan\n')
    print('\n')
    print('Scanning now...')
    print('\n')
    #This is wear the progress bar will go
    arguments = '-sV -T5'

    (nm.scan(host, ports, arguments))
    for host in nm.all_hosts():
        #Set state, hostname variable
        state = nm[host].state()
        hostname = nm[host].hostname()
        output = subprocess.check_output(('arp', '-a', host ))
        de_output = output.decode('utf-8')
        splitout = de_output.split(' ')
        #Print host ip address, state and name
        print(f"{crayons.green('IP:')} {host} \n{crayons.green('State:')} 
        {state}\n{crayons.green('Hostname:')} {hostname}")
        print(f"{crayons.green('Mac:')} {splitout[3]}")
        #Loop through scanned protocols
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            #Loop through port in side scanned protocols
            for port in lport:
                print(f"{crayons.green('Protocol:')} {proto}")
                print(f"{crayons.green('Ports:')}")
                print(port,':', nm[host][proto][port]['state'])        
        print(crayons.white('---------------------', bold = True))

def main():
    """Main runtime function"""
    print_figlet_color('Stella Sniffer')
    #with open('vern.txt', 'w') as f:
        #with redirect_stdout(f):
            #print(scan())
    #print(scan())
    scan()
main()



