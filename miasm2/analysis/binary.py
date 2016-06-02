import logging

from miasm2.analysis.machine import Machine
from miasm2.core.asmbloc import asm_symbol_pool
from miasm2.core.bin_stream import bin_stream_str, bin_stream_elf, bin_stream_pe
from miasm2.jitter.csts import PAGE_READ


log = logging.getLogger("binary")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.ERROR)


# Container
## Exceptions
class ContainerSignatureException(Exception):
    "The container does not match the current container signature"


class ContainerParsingException(Exception):
    "Error during container parsing"


## Parent class
class Container(object):
    """Container abstraction layer

    This class aims to offer a common interface for abstracting container
    such as PE or ELF.
    """

    available_container = []  # Available container formats
    fallback_container = None # Fallback container format

    @classmethod
    def from_string(cls, data, vm=None, addr=None):
        """Instanciate a container and parse the binary
        @data: str containing the binary
        @vm: (optional) VmMngr instance to link with the executable
        @addr: (optional) Base address for the binary. If set,
               force the unknown format
        """
        log.info('Load binary')

        if not addr:
            addr = 0
        else:
            # Force fallback mode
            log.warning('Fallback to string input (offset=%s)', hex(addr))
            return cls.fallback_container(data, vm, addr)

        # Try each available format
        for container_type in cls.available_container:
            try:
                return container_type(data, vm)
            except ContainerSignatureException:
                continue
            except ContainerParsingException, error:
                log.error(error)

        # Fallback mode
        log.warning('Fallback to string input (offset=%s)', hex(addr))
        return cls.fallback_container(data, vm, addr)

    @classmethod
    def register_container(cls, container):
        "Add a Container format"
        cls.available_container.append(container)

    @classmethod
    def register_fallback(cls, container):
        "Set the Container fallback format"
        cls.fallback_container = container

    @classmethod
    def from_stream(cls, stream, *args, **kwargs):
        """Instanciate a container and parse the binary
        @stream: stream to use as binary
        @vm: (optional) VmMngr instance to link with the executable
        @addr: (optional) Shift to apply before parsing the binary. If set,
               force the unknown format
        """
        return Container.from_string(stream.read(), *args, **kwargs)

    def parse(self, data, *args, **kwargs):
        "Launch parsing of @data"
        raise NotImplementedError("Abstract method")

    def __init__(self, *args, **kwargs):
        "Alias for 'parse'"
        # Init attributes
        self._executable = None
        self._bin_stream = None
        self._entry_point = None
        self._arch = None
        self._symbol_pool = asm_symbol_pool()

        # Launch parsing
        self.parse(*args, **kwargs)

        # Set disasmEngine
        self.disasmEngine = Machine(self.arch).dis_engine(self.bin_stream)


    def dis_multibloc(self, offset, blocs=None, resolve_address=False):
        return self.disasmEngine.dis_multibloc(offset, blocs)

    @property
    def bin_stream(self):
        "Return the BinStream instance corresponding to container content"
        return self._bin_stream

    @property
    def executable(self):
        "Return the abstract instance standing for parsed executable"
        return self._executable

    @property
    def entry_point(self):
        "Return the detected entry_point"
        return self._entry_point

    @property
    def arch(self):
        "Return the guessed architecture"
        return self._arch

    @property
    def symbol_pool(self):
        "asm_symbol_pool instance preloaded with container and disasmEngine symbols (if any)"
        return self.disasmEngine.symbol_pool

    @property
    def attrib(self):
        "disasmEngine attribute"
        return self.disasmEngine.attrib

    @property
    def disasm_engine(self):
        "disasmEngine"
        return self.disasmEngine


## Format dependent classes
class ContainerPE(Container):
    "Container abstraction for PE"

    def parse(self, data, vm=None):
        from miasm2.jitter.loader.pe import vm_load_pe, guess_arch
        from elfesteem import pe_init

        # Parse signature
        if not data.startswith('MZ'):
            raise ContainerSignatureException()

        # Build executable instance
        try:
            if vm is not None:
                self._executable = vm_load_pe(vm, data)
            else:
                self._executable = pe_init.PE(data)
        except Exception, error:
            raise ContainerParsingException('Cannot read PE: %s' % error)

        # Check instance validity
        if not self._executable.isPE() or \
                self._executable.NTsig.signature_value != 0x4550:
            raise ContainerSignatureException()

        # Guess the architecture
        self._arch = guess_arch(self._executable)

        # Build the bin_stream instance and set the entry point
        try:
            self._bin_stream = bin_stream_pe(self._executable.virt)
            ep_detected = self._executable.Opthdr.AddressOfEntryPoint
            self._entry_point = self._executable.rva2virt(ep_detected)
        except Exception, error:
            raise ContainerParsingException('Cannot read PE: %s' % error)


    def get_symbol_by_addr(self, addr):
        symbols = self._executable.Symbols.symbols
        base_text = 0
        for sect in self._executable.SHList:
            if sect.name == ".text":
                base_text = self._executable.rva2virt(sect.addr)
        searched_offset = addr - base_text
        for sym in symbols:
            if sym.value == searched_offset:
                return sym.name, 0

        return None, 0

    def get_all_symbols(self):
        symbols_map = { }
        symbols = [ x for x in self._executable.Symbols.symbols if
                   x.type == 0x20 ]
        base_text = 0
        for sect in self._executable.SHList:
            if sect.name.rstrip('\x00') == ".text":
                base_text = self._executable.rva2virt(sect.addr)
        import_table = self._executable.DirImport
        imported_functions = {}
        for i, s in enumerate(import_table.impdesc):
            imported_functions[s.dlldescname.name] = []
            for ii, f in enumerate(s.impbynames):
                imported_functions[s.dlldescname.name].append(f.name)

        for sym in symbols:
            found = False
            for dll, function_list in imported_functions.iteritems():
                if sym.name in function_list:
                    #TODO check if size is present
                    symbols_map[sym.name + "." + dll + "@extern"] = sym.value + base_text, 0
                    found = True
                    break
            if found:
                continue
            else:
                symbols_map[sym.name] = sym.value + base_text, 0

        return symbols_map


    def get_addr_by_symbol(self, name):
        symbols = self.get_all_symbols()
        for sym, (addr, offset) in symbols.iteritems():
            if sym == name:
                return addr
        return None

    def dis_multibloc(self, offset, blocs=None, resolve_address=False):
        self.disasmEngine.follow_call = True
        blocks = self.disasmEngine.dis_multibloc(offset, blocs)

        # Set symbol pool and relative address
        if resolve_address:
            symbols_map = self.get_all_symbols()
            for label in self.disasmEngine.symbol_pool._labels:
                # If "loc_" is in label.name, we can assume that it has been generated
                if "loc_" in label.name:
                    for sym in symbols_map:
                        base_addr, size = symbols_map[sym]
                        if base_addr <= label.offset < (base_addr + max(size, 1)):
                            relative = label.offset - base_addr
                            newname = sym + (("+0x%x" % relative) if relative else "")
                            self.disasmEngine.symbol_pool.rename_label(label, newname)
                            break
        return blocks


class ContainerELF(Container):
    "Container abstraction for ELF"

    def parse(self, data, vm=None):
        from miasm2.jitter.loader.elf import vm_load_elf, guess_arch
        from elfesteem import elf_init

        # Parse signature
        if not data.startswith('\x7fELF'):
            raise ContainerSignatureException()

        # Build executable instance
        try:
            if vm is not None:
                self._executable = vm_load_elf(vm, data)
            else:
                self._executable = elf_init.ELF(data)
        except Exception, error:
            raise ContainerParsingException('Cannot read ELF: %s' % error)

        # Guess the architecture
        self._arch = guess_arch(self._executable)

        # Build the bin_stream instance and set the entry point
        try:
            self._bin_stream = bin_stream_elf(self._executable.virt)
            self._entry_point = self._executable.Ehdr.entry
        except Exception, error:
            raise ContainerParsingException('Cannot read ELF: %s' % error)


    def get_symbol_in_plt(self, addr):
        rel = self._executable.getsectionbyname(".rel.plt")
        rela = self._executable.getsectionbyname(".rela.plt")
        plt = self._executable.getsectionbyname(".plt")

        for reloc in rel, rela:
            if not reloc:
                continue
            if not (plt.sh.addr <= addr < (plt.sh.size + plt.sh.addr)):
                return None
            index = (addr - plt.sh.addr) / 0x10
            if index >= len(reloc.reltab):
                return None
            else:
                return reloc.reltab[index - 1].sym
        return None


    def get_symbol_by_addr(self, addr):
        """Search for the given address in all available symbols
        """
        symbol = self.get_symbol_in_plt(addr)
        if symbol is None:
            symtab = self._executable.getsectionbyname(".symtab")
            for sym in symtab.symbols:
                if symtab.symbols[sym].value == addr:
                    return sym, symtab.symbols[sym].size;
        else:
            symbol += "@extern"
        return symbol, 0


    def get_all_symbols(self):
        """Create a map between symbol name and their related addresses
        and sizes.
        """
        symbols_map = { }
        symtab = self._executable.getsectionbyname(".symtab")
        for sym in symtab.symtab:
            if sym.name and sym.value:
                symbols_map[sym.name] = sym.value, sym.size

        rel = self._executable.getsectionbyname(".rel.plt")
        rela = self._executable.getsectionbyname(".rela.plt")
        plt = self._executable.getsectionbyname(".plt")

        for reloc in rel, rela:
            if not reloc:
                continue
            index = 0
            for rel_entry in reloc.reltab:
                addr = (index + 1) * 0x10 + plt.sh.addr
                symbols_map[rel_entry.sym + "@extern"] = addr, 0
                index += 1

        return symbols_map


    def get_addr_by_symbol(self, name):
        symtab = self._executable.getsectionbyname(".symtab")
        if name in symtab.symbols:
            return symtab.symbols[name].value
        else:
            return None

    def dis_multibloc(self, offset, blocs=None, resolve_address=False):
        blocks = self.disasmEngine.dis_multibloc(offset, blocs)

        # Set symbol pool and relative address if asked to.
        if resolve_address:
            symbols_map = self.get_all_symbols()
            for label in self.disasmEngine.symbol_pool._labels:
                # If "loc_" is in label.name, we can assume that
                # it has been generated from an address and can be resolved.
                if "loc_" in label.name:
                    for sym in symbols_map:
                        base_addr, size = symbols_map[sym]
                        if base_addr <= label.offset < (base_addr + max(size, 1)):
                            relative = label.offset - base_addr
                            newname = sym + (("+0x%x" % relative) if relative else "")
                            self.disasmEngine.symbol_pool.rename_label(label, newname)
                            break
        return blocks


class ContainerUnknown(Container):
    "Container abstraction for unknown format"

    def parse(self, data, vm, addr):
        self._bin_stream = bin_stream_str(data, shift=addr)
        if vm is not None:
            vm.add_memory_page(addr,
                               PAGE_READ,
                               data)
        self._executable = None
        self._entry_point = 0


## Register containers
Container.register_container(ContainerPE)
Container.register_container(ContainerELF)
Container.register_fallback(ContainerUnknown)
