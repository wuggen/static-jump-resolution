from angr.engines.light import SimEngineLight, SimEngineLightVEXMixin

from .live_definitions import LiveDefinitions, Definition
from .atoms import Atom, Tmp, Register, RegisterOffset, MemoryLocation

import logging
import pyvex.stmt as pyvex
import pyvex.expr as pyvex

l = logging.getLogger(__name__)
#l.setLevel(logging.DEBUG)

class SimEngineSJRVEX(SimEngineLightVEXMixin, SimEngineLight):
    def __init__(self):
        super(SimEngineSJRVEX, self).__init__()

    def _trace(self, name):
        l.info('%s, self.state=%s' % (name, self.state))

    def process(self, state, *args, **kwargs):
        try:
            self._process(state, None, block=kwargs.pop('block', None))
        except SimEngineError as e:
            if kwargs.pop('fail_fast', False):
                raise e
            l.error(e)
        return self.state


    def _process(self, new_state, successors, block=None, whitelist=None):
        if type(new_state) is not LiveDefinitions:
            raise TypeError('Expected LiveDefinitions, got %s' % type(live_defs))

        super(SimEngineSJRVEX, self)._process(new_state, None, block=block)

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

    def _subst_tmps(self, expr):
        return expr
        #if type(expr) is pyvex.RdTmp and expr.tmp in self.tmps:
        #    return self._subst_tmps(self.tmps[expr.tmp])
        #elif type(expr) is pyvex.Qop:
        #    return pyvex.Qop(expr.op, [self._subst_tmps(e) for e in expr.args])
        #elif type(expr) is pyvex.Triop:
        #    return pyvex.Triop(expr.op, [self._subst_tmps(e) for e in expr.args])
        #elif type(expr) is pyvex.Binop:
        #    return pyvex.Binop(expr._op, [self._subst_tmps(e) for e in expr.args], expr.op_int)
        #elif type(expr) is pyvex.Unop:
        #    return pyvex.Unop(expr.op, [self._subst_tmps(e) for e in expr.args])
        #elif type(expr) is pyvex.Load:
        #    return pyvex.Load(expr.end, expr.ty, self._subst_tmps(expr.addr))
        #elif type(expr) is pyvex.ITE:
        #    return pyvex.ITE(
        #            self._subst_tmps(expr.cond),
        #            self._subst_tmps(expr.iftrue),
        #            self._subst_tmps(expr.iffalse))
        #else:
        #    return expr

    def _handle_WrTmp(self, stmt):
        self._trace("_handle_WrTmp before")
        tmp = Tmp(stmt.tmp)
        self.state.kill_and_gen_defs(Definition(tmp, self._codeloc()))
        self._trace("_handle_WrTmp after")

    def _handle_WrTmpData(self, tmp, data):
        self._trace("_handle_WrTmpData before")
        tmp = Tmp(tmp)
        self.state.kill_and_gen_defs(Definition(tmp, self._codeloc()))
        self._trace("_handle_WrTmpData after")

    def _handle_Get(self, expr):
        return self._subst_tmps(expr)

    def _handle_Load(self, expr):
        return self._subst_tmps(expr)
