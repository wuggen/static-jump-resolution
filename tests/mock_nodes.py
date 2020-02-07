from angr.analyses.code_location import CodeLocation

from static_jump_resolution.supergraph import DummyNode
from static_jump_resolution.live_vars import VarUse
from static_jump_resolution.vars import Register
from static_jump_resolution.context import CtxRecord, CallString, ExecutionCtx

DEFAULT_SP = -24
DEFAULT_BP = -8

class CFGNode:
    """ A fake CFGNode class that contains only the information needed directly by the test suite.
    """

    def __init__(self, addr, fn_addr):
        self.addr = addr
        self.function_address = fn_addr

    @property
    def instruction_addrs(self):
        return [self.addr]

    def __eq__(self, other):
        return self.addr == other.addr

    def __hash__(self, other):
        return hash(('CFGNode', self.addr))

    def __repr__(self):
        return '<CFGNode 0x%x>' % self.addr

def arbitrary_call_nodes(num=1):
    """ Get a list of fake call nodes with arbitrary, unique addresses.

    The returned DummyNodes refer to CFGNodes that do not reference any actual CFG analysis or code
    object. The fake addresses of each call site are arbitrary and undefined, except that they are
    distinct from one another and strictly increasing.

    :param int num: The length of the list to generate.
    :return: list of DummyNode call nodes.
    """
    return [DummyNode(CFGNode(addr, addr), 'Dummy_Call') for addr in range(0,num)]

def arbitrary_vars(num=1):
    """ Get a list of arbitrary, unique variables.

    :param int num: The length of the list to generate.
    :return: list of (subclasses of) Var.
    """
    return [Register(-offset, 1) for offset in range(0,num)]

def arbitrary_var_uses(vars, num=1):
    """ Get a collection of uses of the given variables, with arbitrary unique addresses.

    :param int num: The number of uses to generate per var.
    :return: dict mapping variables to a list of their uses.
    """
    return {var: [VarUse(var, CodeLocation(addr, 0)) for addr in range(0, num)] for var in vars}

def arbitrary_records(num=1):
    """ Get a list of fake context records with arbitrary, unique addresses. The stack and base
    pointer values of each record are DEFAULT_SP and DEFAULT_BP respectively.

    :param int num: The length of the list to generate.
    :return: list of CtxRecord, referencing fake call nodes.
    """
    nodes = arbitrary_call_nodes(num)
    return [CtxRecord(node, DEFAULT_SP, DEFAULT_BP) for node in nodes]

def arbitrary_call_string(num=1):
    """ Get a call string of length `num` of arbitrary, unique context records. The stack and base
    pointer values of each record are DEFAULT_SP and DEFAULT_BP respectively.

    :param int num:
    :return: CallString
    """
    return CallString(arbitrary_records(num))

def arbitrary_context():
    """ Get an arbitrary ExecutionCtx.

    The returned context will have stack and base pointer values of DEFAULT_SP and DEFAULT_BP
    respectively, and an arbitrary function address.

    :rtype: ExecutionCtx
    """
    return ExecutionCtx(128, DEFAULT_SP, DEFAULT_BP)
