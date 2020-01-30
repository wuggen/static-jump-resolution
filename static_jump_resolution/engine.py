from angr.engines.light import SimEngineLight, SimEngineLightVEXMixin

from .context import ExecutionCtx
from .live_vars import LiveVars, QualifiedUse, vars_modified, vars_used
from .vars import Var, Register, StackVar, MemoryLocation, memory_location, get_type_size_bytes

from functools import reduce
import operator

import pyvex
import logging

l = logging.getLogger(__name__)

def replace_tmps(expr, tmps):
    """ Recursively replace all IR temporaries in the given expression with their values in the
    given bindings map.

    :param IRExpr expr:
    :param tmps: A mapping from temp indices (int) to IRExpr values.
    :rtype: IRExpr
    """
    if type(expr) is pyvex.IRExpr.RdTmp:
        val = tmps.get(expr.tmp)
        if val is None:
            l.error("[replace_tmps] t%d not bound in the given map" % expr.tmp)
            return expr
        else:
            return replace_tmps(val, tmps)

    elif type(expr) in \
            (pyvex.IRExpr.Qop, pyvex.IRExpr.Triop, pyvex.IRExpr.Binop, pyvex.IRExpr.Unop):
        return type(expr)(expr.op, tuple(replace_tmps(e, tmps) for e in expr.args))

    elif type(expr) is pyvex.IRExpr.Load:
        return pyvex.IRExpr.Load(expr.end, expr.ty, replace_tmps(expr.addr, tmps))

    elif type(expr) is pyvex.IRExpr.ITE:
        return pyvex.IRExpr.ITE(
                replace_tmps(expr.cond, tmps),
                replace_tmps(expr.iffalse, tmps),
                replace_tmps(expr.iftrue, tmps))

    elif type(expr) is pyvex.IRExpr.CCall:
        return pyvex.IRExpr.CCall(expr.retty, expr.cee,
                tuple(replace_tmps(e, tmps) for e in expr.args))

    elif type(expr) in [pyvex.IRExpr.Get, pyvex.IRExpr.Const]:
        return expr

    else:
        l.warning("[replace_tmps] Unimplemented for IRExpr type %s" % type(expr))
        return expr

class SimEngineSJRVEX(SimEngineLightVEXMixin, SimEngineLight):
    def __init__(self):
        self._block_tmps = {}
        super(SimEngineSJRVEX, self).__init__()

    def _trace(self, name):
        l.debug('%s, self.state=%s' % (name, self.state))

    def process(self, state, *args, **kwargs):
        try:
            self._process(state, None, block=kwargs.pop('block', None))
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False):
                raise e
            l.error(e)
        return self.state

    def _preprocess_block(self):
        if self.block.addr in self._block_tmps:
            return

        tmps = {}

        for stmt in self.block.vex.statements:
            if type(stmt) is pyvex.IRStmt.WrTmp:
                tmps[stmt.tmp] = replace_tmps(stmt.data, tmps)

        self._block_tmps[self.block.addr] = tmps

    def _process_Stmt(self, whiltelist=None):
        if whitelist is not None:
            whitelist = set(whitelist)

        self._preprocess_block()

        for (idx, stmt) in enumerate(reversed(self.block.vex.statements)):
            if whitelist is not None and idx not in whitelist:
                continue
            self.stmt_idx = idx

            if type(stmt) is pyvex.IRStmt.IMark:
                self.ins_addr = stmt.addr + stmt.delta
            elif type(stmt) is pyvex.IRStmt.WrTmp:
                continue

            self._handle_Stmt(stmt)

    def _process(self, new_state, successors, block=None, whitelist=None):
        if type(new_state) is not LiveVars:
            raise TypeError('Expected LiveVars, got %s' % type(live_defs))

        super(SimEngineSJRVEX, self)._process(new_state, None, block=block, whitelist=whitelist)

        return self.state

    def _handle_Put(self, stmt):
        self._trace('_handle_Put before')
        offset = stmt.offset
        size = stmt.data.result_size(self.tyenv)

        reg = Register(offset, size)
        self.state.kill_and_gen_defs(Definition(reg, self._codeloc()))
        self._trace('_handle_Put after')

    def _handle_Store(self, stmt):
        self._trace('_handle_Store before')
        addr = self._subst_tmps(stmt.addr)
        size = stmt.data.result_size(self.tyenv)

        memloc = MemoryLocation(addr, size)
        self.state.kill_and_gen_defs(Definition(memloc, self._codeloc()))
        self._trace('_handle_Store after')

    def _handle_WrTmp(self, stmt):
        pass

    def _handle_WrTmpData(self, tmp, data):
        pass
