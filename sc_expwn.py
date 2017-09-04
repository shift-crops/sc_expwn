#!/usr/bin/env python
from pwn import *
from pwnlib.elf.elf import dotdict
import os

p = lambda x: pack(x)
u = lambda x: unpack(x, len(x)*8)

class Environment:
    def __init__(self, *envs):
        self.__env = None
        self.env_list = list(set(envs))
        for env in self.env_list:
            setattr(self, env, dict())

    def set_item(self, name, **obj):
        if obj.keys()!=self.env_list:
            fail('Environment : "%s" environment does not match' % name)
            return
        
        for env in obj:
            getattr(self, env).update({name:obj[env]})

    def select(self, env=None):
        if env is not None and env not in self.env_list:
            warn('Environment : "%s" is not defined' % env)
            env = None
            
        while env is None:
            sel = raw_input('Select Environment\n%s ...' % str(self.env_list)).strip()
            if not sel:
                env = self.env_list[0]
            elif sel in self.env_list:
                env = sel
            else:
                for e in self.env_list:
                    if e.startswith(sel):
                        env = e
                        break

        info('Environment : set environment "%s"' % env)
        for name,obj in getattr(self, env).items():
            setattr(self, name, obj)
        self.__env = env

    def check(self, env):
        return self.__env == env

class ELF(pwnlib.elf.elf.ELF):
    sap_function    = {}
    sap_section     = {}

    def __init__(self, path, checksec=True):
        super(ELF, self).__init__(path, checksec)
        
        self.sep_function   = dotdict()
        self.sep_section    = dotdict()

        self._populate_function()
        self._populate_section()

    @pwnlib.elf.elf.ELF.address.setter
    def address(self, new):
        delta     = new-self._address
        update    = lambda x: x+delta

        self.symbols        = dotdict({k:update(v) for k,v in self.symbols.items()})
        self.plt            = dotdict({k:update(v) for k,v in self.plt.items()})
        self.got            = dotdict({k:update(v) for k,v in self.got.items()})
        self.sep_function   = dotdict({k:update(v) for k,v in self.sep_function.items()})
        self.sep_section    = dotdict({k:update(v) for k,v in self.sep_section.items()})

        # Update our view of memory
        memory = pwnlib.elf.elf.intervaltree.IntervalTree()

        for begin, end, data in self.memory:
            memory.addi(update(begin),
                        update(end),
                        data)

        self.memory = memory

        self._address = update(self.address)

        
    def _populate_function(self):
        for name in self.functions:
            self.sep_function[name] = self.functions[name].address
        
    def _populate_section(self):
        for sec in self.iter_sections():
            self.sep_section[sec.name]  = sec.header.sh_addr

    @property
    def libc(self):
        for lib in self.libs:
            if '/libc.' in lib or '/libc-' in lib:
                return ELF(lib)

def init():
    if 'TMUX' in os.environ:
        if 'DISPLAY' in os.environ:
            del os.environ['DISPLAY']

def communicate(mode='SOCKET', *args, **kwargs):
    if mode == 'SOCKET':
        conn = remote(*args, **kwargs)
    elif mode == 'PROC':
        conn = process(*args, **kwargs)
    elif mode == 'DEBUG':
        if 'argv' in kwargs:
            argv = kwargs['argv']
            del kwargs['argv']
        else:
            argv = './argv'
        conn = gdb.debug(argv, *args, **kwargs)
    else:
        warn('communicate : mode "%s" is not defined' % mode)

    return conn

init()
