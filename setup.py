#!/usr/bin/env python
"""
Copyright Guilherme Moro 2011.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
"""

import sys, os
from distutils.core import setup

if os.name == 'nt':
    print "Windows installation no longer supported. :/"
    sys.exit(1)
else:
	os.system("sed 's:usr:"+sys.prefix[1:]+":' bin/proxydhcpd.in >bin/proxydhcpd")
	os.system("sed 's:usr:"+sys.prefix[1:]+":' scripts/proxydhcpd.sh.in >scripts/proxydhcpd")
	setup(name='proxydhcpd',
    version="0.1",
    license='GPL v2',
    description="proxy DHCP server",
    author='Guilherme Moro',
    author_email='guilherme.moro@gmail.com',
    url='http://github.com/gmoro/proxyDHCPd',
    packages=['proxydhcpd',"proxydhcpd.dhcplib"],
    scripts=['bin/proxydhcpd','proxydhcpd.py'],
    data_files=[("/etc/proxyDHCPd",["proxy.ini"]),
			  ("/etc/init.d",["scripts/proxydhcp"])]
    )
