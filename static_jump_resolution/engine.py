from angr.engines.light import SimEngineLight, SimEngineLightVEXMixin
from angr.block import Block
from angr.errors import SimEngineError

from .context import ExecutionCtx
from .live_vars import LiveVars, QualifiedLiveSet, vars_modified, vars_used, vars_used_expr
from .vars import Var, Register, StackVar, MemoryLocation, memory_location, get_type_size_bytes

from functools import reduce
import operator

import pyvex
from pyvex import IRExpr, IRStmt
import logging

l = logging.getLogger(__name__)

def replace_tmps(expr, tmps):
    """ Recursively replace all IR temporaries in the given expression with their values in the
    given bindings map.

    :param IRExpr expr:
    :param tmps: A mapping from temp indices (int) to IRExpr values.
    :rtype: IRExpr
    """
    if type(expr) is IRExpr.RdTmp:
        val = tmps.get(expr.tmp)
        if val is None:
            l.error("[replace_tmps] t%d not bound in the given map" % expr.tmp)
            return expr
        else:
            return replace_tmps(val, tmps)

    elif type(expr) in \
            (IRExpr.Qop, IRExpr.Triop, IRExpr.Binop, IRExpr.Unop):
        return type(expr)(expr.op, tuple(replace_tmps(e, tmps) for e in expr.args))

    elif type(expr) is IRExpr.Load:
        return IRExpr.Load(expr.end, expr.ty, replace_tmps(expr.addr, tmps))

    elif type(expr) is IRExpr.ITE:
        return IRExpr.ITE(
                replace_tmps(expr.cond, tmps),
                replace_tmps(expr.iffalse, tmps),
                replace_tmps(expr.iftrue, tmps))

    elif type(expr) is IRExpr.CCall:
        return IRExpr.CCall(expr.retty, expr.cee,
                tuple(replace_tmps(e, tmps) for e in expr.args))

    else:
        if type(expr) not in [IRExpr.Get, IRExpr.Const]:
            l.error("[replace_tmps] unimplemented for IRExpr type %s" % type(expr))
        return expr

def replace_tmps_stmt(stmt, tmps):
    """ Recursively replace all IR temporaries in the given statement with their values in the given
    bindings map.

    :param IRStmt stmt:
    :param tmps: A mapping from temp indices (int) to IRExpr values.
    :rtype: IRStmt
    """
    if type(stmt) is IRStmt.Put:
        return IRStmt.Put(replace_tmps(stmt.data, tmps), stmt.offset)

    elif type(stmt) is IRStmt.WrTmp:
        return IRStmt.NoOp()

    elif type(stmt) is IRStmt.Store:
        return IRStmt.Store( \
                replace_tmps(stmt.addr, tmps), \
                replace_tmps(stmt.data, tmps), \
                stmt.end)

    elif type(stmt) is IRStmt.Exit:
        return IRStmt.Exit( \
                replace_tmps(stmt.guard, tmps), \
                replace_tmps(stmt.dst, tmps), \
                stmt.jk, \
                stmt.offsIP)

    else:
        if type(stmt) not in [IRStmt.IMark, IRStmt.AbiHint]:
            l.error("[replace_tmps_stmt] unimplemented for IRStmt type %s" % type(stmt))
        return stmt

def is_indirect_jump(block_or_stmt):
    """ Determine whether the given object encodes an indirect jump, and return its target
    expression if so.

    When given a block, checks if the block ends with an indirect jump. When given a statement,
    checks to see if the statement encodes a (possibly conditional) indirect jump.

    If the given object is not an indirect jump, returns None.

    :param (angr.block.Block or IRStmt) block_or_stmt:
    :rtype: IRExpr or None
    """
    if type(block_or_stmt) is Block:
        block = block_or_stmt
        if block.vex.jumpkind not in ['Ijk_Boring', 'Ijk_Call']:
            return None

        if type(block.vex.next) is not IRExpr.Const:
            return block.vex.next
        else:
            return None

    elif isinstance(block_or_stmt, pyvex.stmt.IRStmt):
        stmt = block_or_stmt
        if type(stmt) is not IRStmt.Exit:
            return None

        if stmt.jumpkind not in ['Ijk_Boring', 'Ijk_Call']:
            return None

        if type(stmt.dst) is not IRExpr.Const:
            return stmt.dst
        else:
            return None

    else:
        raise TypeError("[is_indirect_jump] expected Block or IRStmt argument")

class SimEngineSJRVEX(SimEngineLightVEXMixin, SimEngineLight):
    def __init__(self):
        self._block_tmps = {}
        super(SimEngineSJRVEX, self).__init__()

    def _trace(self, name):
        self.l.debug('%s, self.state=%s' % (name, self.state))

    def process(self, state, *args, **kwargs):
        try:
            self._process(state, None, block=kwargs.pop('block', None))
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False):
                raise e
            self.l.error(e)

        return self.state

    def _process(self, new_state, successors, block=None, whitelist=None):
        """
        :param LiveVars new_state:
        :param successors: Iterable of Block?
        :param angr.block.Block block:
        :param whitelist: Container/iterable of statement indices (int)
        """
        if type(new_state) is not LiveVars:
            raise TypeError('Expected LiveVars, got %s' % type(live_defs))

        super(SimEngineSJRVEX, self)._process(new_state, None, block=block, whitelist=whitelist)

        return self.state

    def _process_Stmt(self, whitelist=None):
        """ Process the statements in the current block. """
        if whitelist is not None:
            whitelist = set(whitelist)

        self._preprocess_block()

        # Unconditionally generate liveness for IJ targets
        if is_indirect_jump(self.block):
            target_vars = vars_used_expr(self.block.vex.next)
            self.state.gen_uses(*target_vars)

        for (idx, stmt) in reversed(list(enumerate(self.block.vex.statements))):
            if whitelist is not None and idx not in whitelist:
                continue
            self.stmt_idx = idx

            if type(stmt) is IRStmt.IMark:
                self.ins_addr = stmt.addr + stmt.delta
            elif type(stmt) is IRStmt.WrTmp:
                continue

            self._handle_Stmt(stmt)

    def _preprocess_block(self):
        """ Scan a block's IR statements and record the values of IR temps.

        Thanks to SSA, this should effectively remove temps as a factor for consideration.
        """
        if self.block.addr in self._block_tmps:
            return

        tmps = {}

        for stmt in self.block.vex.statements:
            if type(stmt) is IRStmt.WrTmp:
                tmps[stmt.tmp] = replace_tmps(stmt.data, tmps)

        self._block_tmps[self.block.addr] = tmps

    @property
    def _tmps(self):
        return self._block_tmps[self.block.addr]

    def _handle_Stmt(self, stmt):
        """ Process a single statement's effects on the current state.

        :param IRStmt stmt:
        """
        stmt = replace_tmps_stmt(stmt, self._tmps)
        used = vars_used(stmt, self.state.execution_ctx, self.state.arch)
        modified = vars_modified(stmt, self.state.execution_ctx, self.state.arch)
        self.state.kill_vars(modified)

        if is_indirect_jump(stmt):
            self.state.gen_uses(used)
        else:
            self.state.gen_uses_if_live(used, modified)
