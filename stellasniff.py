#!/bin/python

import nmap

nm = nmap.PortScanner()

host = '192.168.115.0/24'

nm.scan(hosts='192.168.115.0/24','80')


print('Scanned Hosts:', nm.all_hosts())

print(nm)
print(f'Hosts {host} info:', nm[host])

print(f'Open TCP ports on {host}:')

for port in nm[host].all_tcp():
    portstate = nm[host]['tcp'][port]
    print(f'Port {port}: {portstate}')



