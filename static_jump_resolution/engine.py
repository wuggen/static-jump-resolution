from angr.engines.light import SimEngineLight, SimEngineLightVEXMixin

from .context import ExecutionCtx
from .live_vars import LiveVars, QualifiedUse
from .vars import Var, Register, StackVar, MemoryLocation

import pyvex
from pyvex.const import get_type_size

import operator
import logging

l = logging.getLogger(__name__)
#l.setLevel(logging.DEBUG)

def replace_tmps(expr, tmps):
    """ Replace all IR temporaries in the given expression with their values in
    the given bindings map.

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
            return val

    elif type(expr) is pyvex.IRExpr.GetI:
        return pyvex.IRExpr.GetI(expr.descr, replace_tmps(expr.ix, tmps), expr.bias)

    elif type(expr) in \
            (pyvex.IRExpr.Qop, pyvex.IRExpr.Triop, pyvex.IRExpr.Binop, pyvex.IRExpr.Unop):
        return pyvex.IRExpr.Qop(expr.op, tuple(replace_tmps(e, tmps) for e in expr.args))

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

    else:
        return expr

def stack_var(expr, ctx, arch):
    """ If the expression is an offset from the stack or base pointer, convert it to the
    corresponding StackVar. Otherwise, return None.

    :param IRExpr expr:
    :param ExecutionCtx ctx:
    :param Arch arch:
    :rtype: StackVar or None
    """
    if arch is None:
        return None

    if type(expr) is not pyvex.IRExpr.Load:
        return None

    size = get_type_size(expr.ty)
    addr = expr.addr

    if type(addr) is pyvex.IRExpr.Get:
        if addr.offset == arch.sp_offset:
            return StackVar(ctx.fn, ctx.stack_ptr, size)
        elif addr.offset == arch.bp_offset:
            return StackVar(ctx.fn, ctx.base_ptr, size)
        else:
            return None

    elif type(addr) is pyvex.IRExpr.Binop:
        if not any(type(e) is pyvex.IRExpr.Get for e in addr.args):
            return None
        if not any(type(e) is pyvex.IRExpr.Const for e in addr.args):
            return None

        if addr.op in ('Iop_Add8', 'Iop_Add16', 'Iop_Add32', 'Iop_Add64'):
            op = operator.add_
        elif addr.op in ('Iop_Sub8', 'Iop_Sub16', 'Iop_Sub32', 'Iop_Sub64'):
            op = operator.sub_
        else:
            return None

        (reg, offset) = (addr.args[0], addr.args[1]) \
                if type(addr.args[0]) is pyvex.IRExpr.Get \
                else (addr.args[1], addr.args[0])

        if reg.offset == arch.sp_offset:
            return StackVar(ctx.fn, op(ctx.stack_ptr, offset.value), size)
        elif reg.offset == arch.bp_offset:
            return StackVar(ctx.fn, op(ctx.base_ptr, offset.value), size)
        else:
            return None

    else:
        return None

def vars_modified(stmt, ctx, arch=None):
    """ Get the set of variables modified by the given statement.

    :param IRStmt stmt:
    :param ExecutionCtx ctx: The current execution context.
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    if type(stmt) is pyvex.IRStmt.Put:
        if arch is None or stmt.offset not in (arch.sp_offset, arch.bp_offset, arch.ip_offset):
            return set(Register(stmt.offset, stmt.data.result_size(None)))
        else:
            return set()

    elif type(stmt) is pyvex.IRStmt.Store:
        # TODO: lol still all of this
        pass

def vars_used(stmt, arch=None):
    """ Get the set of variables whose values are used by the given statement.

    :param IRStmt stmt:
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    pass

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
