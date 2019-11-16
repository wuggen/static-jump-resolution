class Atom:
    __slots__ = []

    def __repr__(self):
        raise NotImplementedError

class Tmp(Atom):
    """ An IR temporary variable.

    :param idx: The temp index.

    :ivar idx: The temp index.
    """
    __slots__ = ('idx',)

    def __init__(self, idx):
        self.idx = idx

    def __eq__(self, other):
        return type(other) is Tmp and self.idx == other.idx

    def __hash__(self):
        return hash(('Tmp', self.idx))

    def __repr__(self):
        return 't%d' % self.idx

class Register(Atom):
    """ An architecure register.

    Characterized by its offset in the register file and its size in bytes.

    :param offset: The register offset.
    :param size: The size in bytes.

    :ivar offset: The register offset.
    :ivar size: The size in bytes.
    """
    __slots__ = ('offset', 'size')

    def __init__(self, offset, size):
        self.offset = offset
        self.size = size

    def __eq__(self, other):
        return type(other) is Register and \
                self.offset == other.offset and \
                self.size == other.size

    def __hash__(self):
        return hash(('Register', self.offset, self.size))

    def __repr__(self, arch=None):
        if arch is None:
            return "<Register %s(%s)>" % (self.offset, self.size)
        else:
            return "<Register %s>" % arch.translate_register_name(self.offset, self.size)

class RegisterOffset(Atom):
    """ A memory region characterized as an offset from a register.

    :param Register reg: The base register.
    :param offset: The offset.
    :param size: The size of the region in bytes.

    :ivar reg: The base register.
    :ivar offset: The offset.
    :ivar size: The size of the region in bytes.
    """
    __slots__ = ('reg', 'offset', 'size')

    def __init__(self, reg, offset, size):
        self.reg = reg
        self.offset = offset
        self.size = size

    def __eq__(self, other):
        return type(other) is RegisterOffset and \
                self.reg == other.reg and \
                self.offset == other.offset and \
                self.size == other.size

    def __hash__(self):
        return hash(('RegisterOffset', self.reg, self.offset))

    def __repr__(self, arch=None):
        return "<RegisterOffset %s(%s)>" % (self.reg.__repr__(arch), self.offset)

    def overlaps(self, other):
        """ Determine wether two `RegisterOffset` regions overlap.

        Assumes that two `RegisterOffset`s with different base registers do not overlap.

        :param RegisterOffset other:
        """
        return self.reg == other.reg and \
                self.offset < other.offset + other.size and \
                other.offset < self.offset + self.size

class MemoryLocation(Atom):
    """ An arbitrary memory region characterized by address and size.

    :param addr: The start address of the region.
    :param size: The size of the region in bits.

    :ivar addr: The start addr of the region.
    :ivar size: The size of the region in bits.
    """
    __slots__ = ('addr', 'size')

    def __init__(self, addr, size):
        self.addr = addr
        self.size = size

    def __eq__(self, other):
        return type(other) is MemoryLocation and \
                self.addr == other.addr and \
                self.size == other.size

    def __hash__(self):
        return hash(('MemoryLocation', self.addr, self.size))

    def __repr__(self):
        return '<MemoryLocation %s(%s)>' % (self.addr, self.size)
