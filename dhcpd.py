"""

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

import sys
import logging, logging.handlers
from proxyconfig import parse_config
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

class MyDhcpServer(DhcpNetwork) :
    def __init__(self, listen_address="0.0.0.0", client_listen_port=68,server_listen_port=67) :
        
        DhcpNetwork.__init__(self,listen_address,server_listen_port,client_listen_port)
        
        self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.dhcp_socket.bind((self.listen_address, self.listen_port))

class DHCPD(MyDhcpServer):
    loop = True
    def __init__(self,configfile='proxy.ini',client_port=None,server_port=None):
        self.logger = logging.getLogger('proxydhcp')
        #self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(levelname)s ProxyDHCP: %(message)s')  
        self.consoleLog = logging.StreamHandler()
        self.consoleLog.setFormatter(formatter)
        self.logger.addHandler(self.consoleLog)

        if sys.platform == 'win32':
            self.fileLog = logging.FileHandler('proxy.log')
            self.fileLog.setFormatter(formatter)
            self.logger.addHandler(self.fileLog)
        else:
            if sys.platform == 'darwin':
                self.syslogLog = logging.handlers.SysLogHandler("/var/run/syslog")
            else:
                self.syslogLog = logging.handlers.SysLogHandler("/dev/log")
            self.syslogLog.setFormatter(formatter)
            self.syslogLog.setLevel(logging.INFO)
            self.logger.addHandler(self.syslogLog)
        self.config = parse_config(configfile)
        if not client_port:
            client_port=self.config['proxy']["client_listen_port"]
        if not server_port:
            server_port=self.config['proxy']["server_listen_port"]

        #DhcpServer.__init__(self,self.config['proxy']["listen_address"],client_port,server_port)
        self.log('info',"Starting DHCP on ports client: %s, server: %s"%(client_port,server_port))
        MyDhcpServer.__init__(self,self.config['proxy']["listen_address"],client_port,server_port)

    def HandleDhcpDiscover(self, packet):
        #print str()+"--------------sadosijdiad"
        #if packet.IsOption('class_identifier'):
        if packet.IsOption('vendor_class_identifier'):
            class_identifier = strlist(packet.GetOption('vendor_class_identifier'))
            responsepacket = DhcpPacket()
            responsepacket.CreateDhcpOfferPacketFrom(packet)
            responsepacket.SetMultipleOptions( {
                'hlen': packet.GetOption("hlen"),
                'htype': packet.GetOption("htype"),
                'xid': packet.GetOption("xid"),
                'flags': packet.GetOption("flags"),
                'giaddr': packet.GetOption("giaddr")
            } )
            if class_identifier.str()[0:9] == "PXEClient":
                responsepacket.SetMultipleOptions( {
                    "yiaddr":[0,0,0,0],
                    #'siaddr': self.config['pxe']['tftpd'],
                    #'file': map(ord, (self.config['pxe']['filename'].ljust(128,"\0"))),
                    'vendor_class_identifier': map(ord, "PXEClient"),#\0"),
                    #'vendor_specific_information': map(ord,"\x06\x01\x08"),
                    'server_identifier':map(int, self.config['proxy']["listen_address"].split(".")),# self.config['pxe']['tftpd'], # This is incorrect but apparently makes certain Intel cards happy
                    #'bootfile_name': map(ord, self.config['pxe']['filename'] + "\0"),
                    #'tftp_server_name': map(ord, ".".join(map(str,self.config['pxe']['tftpd'])))
                } )
                responsepacket.DeleteOption('ip_address_lease_time')
                ####################
                ###################
                ##################
                self.SendDhcpPacketTo(responsepacket, "255.255.255.255", 68)
                #self.SendDhcpPacketTo("255.255.255.255", responsepacket)
                ##################
                ###################
                ####################
                #self.log('info','Trying to send %s to client as filename'%str(self.config['pxe']['filename']))
                #self.log('info','Trying to send %s to client'%str(".".join(map(str,self.config['pxe']['tftpd']))))
                self.log('info','******Responded to PXE Discover from ' + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
            else:
                self.log('debug','2Noticed a non-boot DHCP Discover packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
        else:
            self.log('debug','1Noticed a non-boot DHCP Discover packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpRequest(self, packet):
        self.log('debug','Noticed a DHCP Request (port 67) packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
        #if packet.IsOption('class_identifier'):
        #    class_identifier = strlist(packet.GetOption('class_identifier'))
        #    responsepacket = DhcpPacket()
        #    #responsepacket.CreateDhcpOfferPacketFrom(packet)
        #    responsepacket.CreateDhcpAckPacketFrom(packet)
        #    responsepacket.SetMultipleOptions( {
        #        'hlen': packet.GetOption("hlen"),
        #        'htype': packet.GetOption("htype"),
        #        'xid': packet.GetOption("xid"),
        #        'flags': packet.GetOption("flags"),
        #        'giaddr': packet.GetOption("giaddr")
        #    } )
        #    if class_identifier.str()[0:9] == "PXEClient":
        #        responsepacket.SetMultipleOptions( {
        #            "yiaddr":[0,0,0,0],
        #            'siaddr': self.config['pxe']['tftpd'],
        #            'file': map(ord, (self.config['pxe']['filename'].ljust(128,"\0"))),
        #            'class_identifier': map(ord, "PXEClient\0"),
        #            'vendor_specific_information': map(ord,"\x06\x01\x08"),
        #            'server_identifier': self.config['pxe']['tftpd'],
        #            #'server_identifier': map(ord, ".".join(map(str,self.config['pxe']['tftpd']))),# This is incorrect but apparently makes certain Intel cards happy
        #            'bootfile_name': map(ord, self.config['pxe']['filename'] + "\0"),
        #            'tftp_server_name': self.config['pxe']['tftpd']
        #        } )
        #        responsepacket.DeleteOption('ip_address_lease_time')
        #        self.SendDhcpPacketTo("255.255.255.255", responsepacket)
        ##        self.log('info','Trying to send %s to client as filename'%str(self.config['pxe']['filename']))
        ##        self.log('info','Trying to send %s to client'%str(".".join(map(str,self.config['pxe']['tftpd']))))
        #        self.log('info','****Responded a DHCP request on port 67 ' + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpDecline(self, packet):
        self.log('debug','Noticed a DHCP Decline packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpRelease(self, packet):
        self.log('debug','Noticed a DHCP Release packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpInform(self, packet):
        self.log('debug','Noticed a DHCP Inform packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def log(self,level,message):
        if level == 'info':
            self.logger.info(message)
        else:
            self.logger.debug(message)
    def run(self):
        while self.loop:
            self.GetNextDhcpPacket()
        self.log('info','Service shutdown')

    def fmtHex(self,input):
        input=hex(input)
        input=str(input)
        input=input.replace("0x","")
        if len(input)==1:
            input="0"+input
        return input

class ProxyDHCPD(DHCPD):
    loop = True
    def __init__(self,configfile='proxy.ini',client_port=None,server_port="4011"):
        self.config = parse_config(configfile)
        if not client_port:
            client_port=self.config['proxy']["client_listen_port"]
        
        #DhcpServer.__init__(self,self.config['proxy']["listen_address"],client_port,server_port)
        DHCPD.__init__(self,configfile,server_port="4011")

    def HandleDhcpDiscover(self, packet):
        self.log('debug','Noticed a DHCP Discover packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
    
    def HandleDhcpRequest(self, packet):
#        self.log('debug','Noticed a DHCP Request packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))
        if packet.IsOption('vendor_class_identifier'):
            
            class_identifier = strlist(packet.GetOption('vendor_class_identifier'))
            responsepacket = DhcpPacket()
            responsepacket.CreateDhcpAckPacketFrom(packet)
            responsepacket.SetMultipleOptions( {
                'hlen': packet.GetOption("hlen"),
                'htype': packet.GetOption("htype"),
                'xid': packet.GetOption("xid"),
                'flags': packet.GetOption("flags"),
                'giaddr': packet.GetOption("giaddr")
            } )
            if class_identifier.str()[0:9] == "PXEClient":
                responsepacket.SetMultipleOptions( {
                    "yiaddr":[0,0,0,0],
                    'siaddr': self.config['pxe']['tftpd'],
                    'file': map(ord, (self.config['pxe']['filename'].ljust(128,"\0"))),
                    'vendor_class_identifier': map(ord, "PXEClient"),#\0"),
                    'vendor_specific_information': map(ord,"\x06\x01\x08"),
                    'server_identifier': map(int, self.config['proxy']["listen_address"].split(".")), # This is incorrect but apparently makes certain Intel cards happy
                    'bootfile_name': map(ord, self.config['pxe']['filename'] + "\0"),
                    'tftp_server_name': self.config['pxe']['tftpd']
                } )
                responsepacket.DeleteOption('ip_address_lease_time')
                self.SendDhcpPacketTo(responsepacket, ".".join(map(str,packet.GetOption('ciaddr'))), 68)
                #self.SendDhcpPacketTo(".".join(map(str,packet.GetOption('ciaddr'))), responsepacket)
                #self.log('info','Trying to send %s to client as filename'%str(self.config['pxe']['filename']))
                #self.log('info','Trying to send %s to client'%str(".".join(map(str,self.config['pxe']['tftpd']))))
                self.log('info','****Responded to PXE request (port 4011 ) from ' + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpDecline(self, packet):
        self.log('debug','Noticed a DHCP Decline packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpRelease(self, packet):
        self.log('debug','Noticed a DHCP Release packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def HandleDhcpInform(self, packet):
        self.log('debug','Noticed a DHCP Inform packet from '  + ":".join(map(self.fmtHex,packet.GetHardwareAddress())))

    def log(self,level,message):
        if level == 'info':
            self.logger.info(message)
        else:
            self.logger.debug(message)
    def run(self):
        while self.loop:
            self.GetNextDhcpPacket()
        self.log('info','Service shutdown')

    def fmtHex(self,input):
        input=hex(input)
        input=str(input)
        input=input.replace("0x","")
        if len(input)==1:
            input="0"+input
        return input

#if __name__ == "__main__":
#    dhcpd=DHCPD()
#    while True:
#        dhcpd.run()
