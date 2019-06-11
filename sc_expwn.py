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

class Communicate:
    def __init__(self, mode='SOCKET', *args, **kwargs):
        self.mode = mode
        self.args = args
        self.kwargs = kwargs
        self._conn = None

        self.debug = mode == 'DEBUG'

    def __del(self):
        self._conn.close()

    def connect(self):
        if self._conn is not None:
            self._conn.close()

        if self.mode == 'DEBUG':
            if 'argv' in self.kwargs:
                argv = self.kwargs['argv']
                del self.kwargs['argv']
            else:
                argv = './argv'
            conn = gdb.debug(argv, *self.args, **self.kwargs)
        elif self.mode == 'SOCKET':
            conn = remote(*self.args, **self.kwargs)
        elif self.mode == 'PROC':
            conn = process(*self.args, **self.kwargs)
        elif self.mode == 'SSH':
            need_shell = False
            if 'raw' in self.kwargs:
                need_shell = self.kwargs['raw']
                del self.kwargs['raw']

            conn = ssh(*self.args, **self.kwargs)
            if need_shell:
                conn = conn.shell()
        else:
            warn('communicate : self.mode "%s" is not defined' % self.mode)
            conn = None

        self._conn = conn
        return conn

    def run(self, func, **kwargs):
        return func(self._conn, **kwargs)

    def bruteforce(self, func, **kwargs):
        if self.debug:
            warn('bruteforce : disabled bruteforce in debug mode')
            self.run(func, **kwargs)
        else:
            while True:
                try:
                    self.run(func, **kwargs)
                except:
                    self.connect()
                else:
                    break

    def repeat(self, func, break_lv, *args, **kwargs):
        arg = kwargs['arg'] if 'arg' in kwargs else []
        level = len(arg)
        nests = len(args)

        for x in args[0]:
            kwargs['arg'] = arg + [x]
            try:
                if nests > 1:
                    self.repeat(func, break_lv, *args[1:], **kwargs)
                else:
                    self.run(func, **kwargs)
            except Exception as e:
                if level > break_lv:
                    raise e
                else:
                    self.connect()
            else:
                if level >= break_lv:
                    self.connect()
                    break

    @property
    def connection(self):
        return self._conn

# for backward compatibility
def communicate(mode='SOCKET', *args, **kwargs):
    comn = Communicate(mode, *args, **kwargs)
    return comn.connect()

def init():
    if 'TMUX' in os.environ:
        if 'DISPLAY' in os.environ:
            del os.environ['DISPLAY']

init()
