# pydhcplib
# Copyright (C) 2008 Mathieu Ignacio -- mignacio@april.org
#
# This file is part of pydhcplib.
# Pydhcplib is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import operator
from struct import unpack
from struct import pack
# from dhcp_basic_packet import *
from dhcp_constants import *
from type_ipv4 import ipv4
from type_strlist import strlist
from type_hwmac import hwmac
import sys

class DhcpPacket():
    def __init__(self):

        self.packet_data = [0]*240
        self.options_data = {}
        self.packet_data[236:240] = MagicCookie
        self.source_address = False

        # print "testing init"
        # print self.packet_data
        
    def IsDhcpPacket(self):
        if self.packet_data[236:240] != MagicCookie : return False
        return True

    # Check if variable is a list with int between 0 and 255
    def CheckType(self,variable):
        if type(variable) == list :
            for each in variable :
                if (type(each) != int)  or (each < 0) or (each > 255) :
                    return False
            return True
        else : return False
        

    def DeleteOption(self,name):
        # if name is a standard dhcp field
        # Set field to 0
        if DhcpFields.has_key(name) :
            begin = DhcpFields[name][0]
            end = DhcpFields[name][0]+DhcpFields[name][1]
            self.packet_data[begin:end] = [0]*DhcpFields[name][1]
            return True

        # if name is a dhcp option
        # delete option from self.option_data
        elif self.options_data.has_key(name) :
            # forget how to remove a key... try delete
            self.options_data.__delitem__(name)
            return True

        return False

    def GetOption(self,name):
        if DhcpFields.has_key(name) :
            option_info = DhcpFields[name]
            return self.packet_data[option_info[0]:option_info[0]+option_info[1]]

        elif self.options_data.has_key(name) :
            return self.options_data[name]

        return []
        

    def SetOption(self,name,value):

        # Basic value checking :
        # has value list a correct length

        # print "testing setoption"
        # print self.packet_data

        # if name is a standard dhcp field
        if DhcpFields.has_key(name) :
            if len(value) != DhcpFields[name][1] :
                sys.stderr.write( "pydhcplib.dhcp_basic_packet.setoption error, bad option length : "+name)
                return False
            begin = DhcpFields[name][0]
            end = DhcpFields[name][0]+DhcpFields[name][1]
            self.packet_data[begin:end] = value
            return True

        # if name is a dhcp option
        elif DhcpOptions.has_key(name) :

            # fields_specs : {'option_code':fixed_length,minimum_length,multiple}
            # if fixed_length == 0 : minimum_length and multiple apply
            # else : forget minimum_length and multiple 
            # multiple : length MUST be a multiple of 'multiple'
            # FIXME : this definition should'nt be in dhcp_constants ?
            fields_specs = { "ipv4":[4,0,1], "ipv4+":[0,4,4],
                             "string":[0,0,1], "bool":[1,0,1],
                             "char":[1,0,1], "16-bits":[2,0,1],
                             "32-bits":[4,0,1], "identifier":[0,2,1],
                             "RFC3397":[0,4,1],"none":[0,0,1],"char+":[0,1,1]
                             }
            
            specs = fields_specs[DhcpOptionsTypes[DhcpOptions[name]]]
            length = len(value)
            if (specs[0]!=0 and specs==length) or (specs[1]<=length and length%specs[2]==0):
                self.options_data[name] = value
                return True
            else :
                return False

        sys.stderr.write( "pydhcplib.dhcp_basic_packet.setoption error : unknown option "+name)
        return False



    def IsOption(self,name):
        if self.options_data.has_key(name) : return True
        elif DhcpFields.has_key(name) : return True
        else : return False

    # Encode Packet and return it
    def EncodePacket(self):

        # MUST set options in order to respect the RFC (see router option)
        order = {}

        for each in self.options_data.keys() :
            order[DhcpOptions[each]] = []
            order[DhcpOptions[each]].append(DhcpOptions[each])
            order[DhcpOptions[each]].append(len(self.options_data[each]))
            order[DhcpOptions[each]] += self.options_data[each]
            
        options = []

        for each in sorted(order.keys()) : options += (order[each])

        packet = self.packet_data[:240] + options
        packet.append(255) # add end option
        pack_fmt = str(len(packet))+"c"

        packet = map(chr,packet)
        
        return pack(pack_fmt,*packet)


    # Insert packet in the object
    def DecodePacket(self,data,debug=False):
        self.packet_data = []
        self.options_data = {}

        if (not data) : return False
        # we transform all data to int list
        unpack_fmt = str(len(data)) + "c"
        for i in unpack(unpack_fmt,data):
            self.packet_data.append(ord(i))

        # Some servers or clients don't place magic cookie immediately
        # after headers and begin options fields only after magic.
        # These 4 lines search magic cookie and begin iterator after.
        iterator = 236
        end_iterator = len(self.packet_data)
        while ( self.packet_data[iterator:iterator+4] != MagicCookie and iterator < end_iterator) :
            iterator += 1
        iterator += 4
        
        # parse extended options

        while iterator < end_iterator :
            if self.packet_data[iterator] == 0 : # pad option
                opt_first = iterator+1
                iterator += 1

            elif self.packet_data[iterator] == 255 :
                self.packet_data = self.packet_data[:240] # base packet length without magic cookie
                return
                
            elif DhcpOptionsTypes.has_key(self.packet_data[iterator]) and self.packet_data[iterator]!= 255:
                opt_len = self.packet_data[iterator+1]
                opt_first = iterator+1
                self.options_data[DhcpOptionsList[self.packet_data[iterator]]] = self.packet_data[opt_first+1:opt_len+opt_first+1]
                iterator += self.packet_data[opt_first] + 2
            else :
                opt_first = iterator+1
                iterator += self.packet_data[opt_first] + 2

        # cut packet_data to remove options
        
        self.packet_data = self.packet_data[:240] # base packet length with magic cookie


    def str(self):
        # Process headers : 
        printable_data = "# Header fields\n"

        op = self.packet_data[DhcpFields['op'][0]:DhcpFields['op'][0]+DhcpFields['op'][1]]
        printable_data += "op : " + DhcpFieldsName['op'][str(op[0])] + "\n"

        
        for opt in  ['htype','hlen','hops','xid','secs','flags',
                     'ciaddr','yiaddr','siaddr','giaddr','chaddr','sname','file'] :
            begin = DhcpFields[opt][0]
            end = DhcpFields[opt][0]+DhcpFields[opt][1]
            data = self.packet_data[begin:end]
            result = ''
            if DhcpFieldsTypes[opt] == "int" : result = str(data[0])
            elif DhcpFieldsTypes[opt] == "int2" : result = str(data[0]*256+data[1])
            elif DhcpFieldsTypes[opt] == "int4" : result = str(ipv4(data).int())
            elif DhcpFieldsTypes[opt] == "str" :
                for each in data :
                    if each != 0 : result += chr(each)
                    else : break

            elif DhcpFieldsTypes[opt] == "ipv4" : result = ipv4(data).str()
            elif DhcpFieldsTypes[opt] == "hwmac" :
                result = []
                hexsym = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
                for iterator in range(6) :
                    result += [str(hexsym[data[iterator]/16]+hexsym[data[iterator]%16])]

                result = ':'.join(result)

            printable_data += opt+" : "+result  + "\n"

        # Process options : 
        printable_data += "# Options fields\n"

        for opt in self.options_data.keys():
            data = self.options_data[opt]
            result = ""
            optnum  = DhcpOptions[opt]
            if opt=='dhcp_message_type' : result = DhcpFieldsName['dhcp_message_type'][str(data[0])]
            elif DhcpOptionsTypes[optnum] == "char" : result = str(data[0])
            elif DhcpOptionsTypes[optnum] == "16-bits" : result = str(data[0]*256+data[0])
            elif DhcpOptionsTypes[optnum] == "32-bits" : result = str(ipv4(data).int())
            elif DhcpOptionsTypes[optnum] == "string" :
                for each in data :
                    if each != 0 : result += chr(each)
                    else : break
        
            elif DhcpOptionsTypes[optnum] == "ipv4" : result = ipv4(data).str()
            elif DhcpOptionsTypes[optnum] == "ipv4+" :
                for i in range(0,len(data),4) :
                    if len(data[i:i+4]) == 4 :
                        result += ipv4(data[i:i+4]).str() + " - "
            elif DhcpOptionsTypes[optnum] == "char+" :
                if optnum == 55 : # parameter_request_list
                    result = ','.join([DhcpOptionsList[each] for each in data])
                else : result += str(data)
                
            printable_data += opt + " : " + result + "\n"

        return printable_data

    def AddLine(self,_string) :
        (parameter,junk,value) = _string.partition(':')
        parameter = parameter.strip()
        # If value begin with a whitespace, remove it, leave others
        if len(value)>0 and value[0] == ' ' : value = value[1:]
        value = self._OptionsToBinary(parameter,value)
        if value : self.SetOption(parameter,value)

    def _OptionsToBinary(self,parameter,value) :
        # Transform textual data into dhcp binary data

        p = parameter.strip()
        # 1- Search for header informations or specific parameter
        if p == 'op' or p == 'htype' :
            value = value.strip()
            if value.isdigit() : return [int(value)]
            try :
                value = DhcpNames[value.strip()]
                return [value]
            except KeyError :
                return [0]

        elif p == 'hlen' or p == 'hops' :
            try :
                value = int(value)
                return [value]
            except ValueError :
                return [0]

        elif p == 'secs' or p == 'flags' :
            try :
                value = ipv4(int(value)).list()
            except ValueError :
                value = [0,0,0,0]

            return value[2:]

        elif p == 'xid' :
            try :
                value = ipv4(int(value)).list()
            except ValueError :
                value = [0,0,0,0]
            return value

        elif p == 'ciaddr' or p == 'yiaddr' or p == 'siaddr' or p == 'giaddr' :
            try :
                ip = ipv4(value).list()
            except ValueError :
                ip = [0,0,0,0]
            return ip
        
        elif p == 'chaddr' :
            try:
                value = hwmac(value).list()+[0]*10
            except ValueError,TypeError :
                value = [0]*16
            return value
            
        elif p == 'sname' :
            return
        elif p == 'file' :
            return
        elif p == 'parameter_request_list' :
            value = value.strip().split(',')
            tmp = []
            for each in value:
                if DhcpOptions.has_key(each) : tmp.append(DhcpOptions[each])
            return tmp
        elif  p=='dhcp_message_type' :
            try :
                return [DhcpNames[value]]
            except KeyError:
                return

        # 2- Search for options
        try : option_type = DhcpOptionsTypes[DhcpOptions[parameter]]
        except KeyError : return False

        if option_type == "ipv4" :
            # this is a single ip address
            try :
                binary_value = map(int,value.split("."))
            except ValueError : return False
            
        elif option_type == "ipv4+" :
            # this is multiple ip address
            iplist = value.split(",")
            opt = []
            for single in iplist :
                opt += (ipv4(single).list())
            binary_value = opt

        elif option_type == "32-bits" :
            # This is probably a number...
            try :
                digit = int(value)
                binary_value = [digit>>24&0xFF,(digit>>16)&0xFF,(digit>>8)&0xFF,digit&0xFF]
            except ValueError :
                return False

        elif option_type == "16-bits" :
            try :
                digit = int(value)
                binary_value = [(digit>>8)&0xFF,digit&0xFF]
            except ValueError : return False


        elif option_type == "char" :
            try :
                digit = int(value)
                binary_value = [digit&0xFF]
            except ValueError : return False

        elif option_type == "bool" :
            if value=="False" or value=="false" or value==0 :
                binary_value = [0]
            else : binary_value = [1]
            
        elif option_type == "string" :
            binary_value = strlist(value).list()

        else :
            binary_value = strlist(value).list()
        
        return binary_value
    
    # FIXME: This is called from IsDhcpSomethingPacket, but is this really
    # needed?  Or maybe this testing should be done in
    # DhcpBasicPacket.DecodePacket().

    # Test Packet Type
    def IsDhcpSomethingPacket(self,type):
        if self.IsDhcpPacket() == False : return False
        if self.IsOption("dhcp_message_type") == False : return False
        if self.GetOption("dhcp_message_type") != type : return False
        return True
    
    def IsDhcpDiscoverPacket(self):
        return self.IsDhcpSomethingPacket([1])

    def IsDhcpOfferPacket(self):
        return self.IsDhcpSomethingPacket([2])

    def IsDhcpRequestPacket(self):
        return self.IsDhcpSomethingPacket([3])

    def IsDhcpDeclinePacket(self):
        return self.IsDhcpSomethingPacket([4])

    def IsDhcpAckPacket(self):
        return self.IsDhcpSomethingPacket([5])

    def IsDhcpNackPacket(self):
        return self.IsDhcpSomethingPacket([6])

    def IsDhcpReleasePacket(self):
        return self.IsDhcpSomethingPacket([7])

    def IsDhcpInformPacket(self):
        return self.IsDhcpSomethingPacket([8])


    def GetMultipleOptions(self,options=()):
        result = {}
        for each in options:
            result[each] = self.GetOption(each)
        return result

    def SetMultipleOptions(self,options={}):
        for each in options.keys():
            self.SetOption(each,options[each])






    # Creating Response Packet

    # Server-side functions
    # From RFC 2132 page 28/29
    def CreateDhcpOfferPacketFrom(self,src): # src = discover packet
        self.SetOption("htype",src.GetOption("htype"))
        self.SetOption("xid",src.GetOption("xid"))
        self.SetOption("flags",src.GetOption("flags"))
        self.SetOption("giaddr",src.GetOption("giaddr"))
        self.SetOption("chaddr",src.GetOption("chaddr"))
        self.SetOption("ip_address_lease_time",src.GetOption("ip_address_lease_time"))
        self.TransformToDhcpOfferPacket()

    def TransformToDhcpOfferPacket(self):
        self.SetOption("dhcp_message_type",[2])
        self.SetOption("op",[2])
        self.SetOption("hlen",[6]) 

        self.DeleteOption("secs")
        self.DeleteOption("ciaddr")
        self.DeleteOption("request_ip_address")
        self.DeleteOption("parameter_request_list")
        self.DeleteOption("client_identifier")
        self.DeleteOption("maximum_message_size")





    """ Dhcp ACK packet creation """
    def CreateDhcpAckPacketFrom(self,src): # src = request or inform packet
        self.SetOption("htype",src.GetOption("htype"))
        self.SetOption("xid",src.GetOption("xid"))
        self.SetOption("ciaddr",src.GetOption("ciaddr"))
        self.SetOption("flags",src.GetOption("flags"))
        self.SetOption("giaddr",src.GetOption("giaddr"))
        self.SetOption("chaddr",src.GetOption("chaddr"))
        self.SetOption("ip_address_lease_time",src.GetOption("ip_address_lease_time"))
        self.TransformToDhcpAckPacket()

    def TransformToDhcpAckPacket(self): # src = request or inform packet
        self.SetOption("op",[2])
        self.SetOption("hlen",[6]) 
        self.SetOption("dhcp_message_type",[5])

        self.DeleteOption("secs")
        self.DeleteOption("request_ip_address")
        self.DeleteOption("parameter_request_list")
        self.DeleteOption("client_identifier")
        self.DeleteOption("maximum_message_size")


    """ Dhcp NACK packet creation """
    def CreateDhcpNackPacketFrom(self,src): # src = request or inform packet
        
        self.SetOption("htype",src.GetOption("htype"))
        self.SetOption("xid",src.GetOption("xid"))
        self.SetOption("flags",src.GetOption("flags"))
        self.SetOption("giaddr",src.GetOption("giaddr"))
        self.SetOption("chaddr",src.GetOption("chaddr"))
        self.TransformToDhcpNackPacket()

    def TransformToDhcpNackPacket(self):
        self.SetOption("op",[2])
        self.SetOption("hlen",[6]) 
        self.DeleteOption("secs")
        self.DeleteOption("ciaddr")
        self.DeleteOption("yiaddr")
        self.DeleteOption("siaddr")
        self.DeleteOption("sname")
        self.DeleteOption("file")
        self.DeleteOption("request_ip_address")
        self.DeleteOption("ip_address_lease_time")
        self.DeleteOption("parameter_request_list")
        self.DeleteOption("client_identifier")
        self.DeleteOption("maximum_message_size")
        self.SetOption("dhcp_message_type",[6])







    """ GetClientIdentifier """

    def GetClientIdentifier(self) :
        if self.IsOption("client_identifier") :
            return self.GetOption("client_identifier")
        return []

    def GetGiaddr(self) :
        return self.GetOption("giaddr")

    def GetHardwareAddress(self) :
        length = self.GetOption("hlen")[0]
        full_hw = self.GetOption("chaddr")
        if length!=[] and length<len(full_hw) : return full_hw[0:length]
        return full_hw

