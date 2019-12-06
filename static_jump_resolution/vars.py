class Var:
    __slots__ = tuple()

    def __repr__(self):
        raise NotImplementedError

class Register(Var):
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

class StackVar(Var):
    """ A function-local variable, characterized by an offset within a stack frame and a byte size.

    The value of the stack pointer at the time a function begins execution is defined to be 0. Therefore,
    negative offsets refer to variables defined within the body of the function, while positive offsets
    refer to parameters passed on the stack.

    :param fn: The function to which this variable is local.
    :param offset: The offset.
    :param size: The size of the region in bytes.

    :ivar fn: The function to which this variable is local.
    :ivar offset: The offset.
    :ivar size: The size of the region in bytes.
    """
    __slots__ = ('fn', 'offset', 'size')

    def __init__(self, fn, offset, size):
        self.fn = fn
        self.offset = offset
        self.size = size

    def __eq__(self, other):
        return type(other) is StackVar and \
                self.fn == other.fn and \
                self.offset == other.offset and \
                self.size == other.size

    def __hash__(self):
        return hash(('StackVar', self.fn, self.offset, self.size))

    def __repr__(self, arch=None):
        return "<StackVar %s(%s)>" % (self.reg.__repr__(arch), self.offset)

    def overlaps(self, other):
        """ Determine whether two `StackVar` regions overlap.

        :param RegisterOffset other:
        """
        return self.fn == other.fn and \
                self.offset < other.offset + other.size and \
                other.offset < self.offset + self.size

class MemoryLocation(Var):
    """ An arbitrary (non-local) memory region characterized by address and size.

    :param addr: The start address of the region. Usually an IR expression rather than an absolute address.
    :param size: The size of the region in bits.

    :ivar addr: The start addr of the region. Usually an IR expression rather than an absolute address.
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
