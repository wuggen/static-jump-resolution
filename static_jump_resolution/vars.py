from .context import ExecutionCtx

import pyvex
import operator

def get_type_size_bytes(ty):
    return pyvex.const.get_type_size(ty) / 8

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

    :param fn_addr: The address of the function to which this variable is local.
    :param offset: The stack frame offset.
    :param size: The size of the region in bytes.

    :ivar fn_addr: The address of the function to which this variable is local.
    :ivar offset: The stack frame offset.
    :ivar size: The size of the region in bytes.
    """
    __slots__ = ('fn_addr', 'offset', 'size')

    def __init__(self, fn_addr, offset, size):
        self.fn_addr = fn_addr
        self.offset = offset
        self.size = size

    def __eq__(self, other):
        return type(other) is StackVar and \
                self.fn_addr == other.fn_addr and \
                self.offset == other.offset and \
                self.size == other.size

    def __hash__(self):
        return hash(('StackVar', self.fn_addr, self.offset, self.size))

    def __repr__(self):
        return "<StackVar [0x%x] %d (%d bytes)>" % (self.fn_addr, self.offset, self.size)

    def overlaps(self, other):
        """ Determine whether two `StackVar` regions overlap.

        :param RegisterOffset other:
        """
        return self.fn_addr == other.fn_addr and \
                self.offset < other.offset + other.size and \
                other.offset < self.offset + self.size

class MemoryLocation(Var):
    """ An arbitrary (non-local) memory region characterized by address and size.

    :param addr: The start address of the region. Usually an IR expression rather than an absolute address.
    :param size: The size of the region in bytes.

    :ivar addr: The start addr of the region. Usually an IR expression rather than an absolute address.
    :ivar size: The size of the region in bytes.
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

def stack_var(addr, ctx, arch, ty):
    """ If the expression is an offset from the stack or base pointer, return the corresponding
    StackVar. Otherwise, return None.

    :param IRExpr addr:
    :param ExecutionCtx ctx:
    :param Arch arch:
    :param ty: The type of the load or store that uses the given expression as an address.
    :rtype: StackVar or None
    """
    if arch is None:
        return None

    size = get_type_size_bytes(ty)

    # Either a direct dereference of the SP/BP...
    if type(addr) is pyvex.IRExpr.Get:
        if addr.offset == arch.sp_offset:
            return StackVar(ctx.fn_addr, ctx.stack_ptr, size)
        elif addr.offset == arch.bp_offset:
            return StackVar(ctx.fn_addr, ctx.base_ptr, size)
        else:
            return None

    # Or the SP/BP register plus/minus a constant
    elif type(addr) is pyvex.IRExpr.Binop:
        if not any(type(e) is pyvex.IRExpr.Get for e in addr.args):
            return None
        if not any(type(e) is pyvex.IRExpr.Const for e in addr.args):
            return None

        # Get the operator (add/sub)
        if addr.op in ('Iop_Add8', 'Iop_Add16', 'Iop_Add32', 'Iop_Add64'):
            op = operator.add
        elif addr.op in ('Iop_Sub8', 'Iop_Sub16', 'Iop_Sub32', 'Iop_Sub64'):
            op = operator.sub
        else:
            return None

        # Figure out which argument is the register and which is the offset
        (reg, offset) = (addr.args[0], addr.args[1]) \
                if type(addr.args[0]) is pyvex.IRExpr.Get \
                else (addr.args[1], addr.args[0])

        if reg.offset == arch.sp_offset:
            return StackVar(ctx.fn_addr, op(ctx.stack_ptr, offset.con.value), size)
        elif reg.offset == arch.bp_offset:
            return StackVar(ctx.fn_addr, op(ctx.base_ptr, offset.con.value), size)
        else:
            return None

    else:
        return None

def memory_location(addr, ctx, arch, ty):
    """ Return the MemoryLocation or StackVar corresponding to the given expression interpretted as
    a memory address.

    :param IRExpr expr:
    :param ExecutionCtx ctx:
    :param Arch arch:
    :param ty: The type of the memory access.
    :rtype: StackVar or MemoryLocation or None
    """
    mb_stack_var = stack_var(addr, ctx, arch, ty)
    if mb_stack_var:
        return mb_stack_var
    else:
        return MemoryLocation(addr, get_type_size_bytes(ty))
