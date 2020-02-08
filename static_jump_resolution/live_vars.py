from angr.analyses.code_location import CodeLocation

from .context import CtxRecord, CallString, ExecutionCtx
from .vars import Var, Register, StackVar, MemoryLocation, memory_location, get_type_size_bytes

import operator
from functools import reduce

import pyvex
from pyvex import IRExpr, IRStmt
import logging

l = logging.getLogger(__name__)

class VarUse:
    """ A use of a variable at a particular program point.

    :param Var var:
    :param CodeLocation codeloc:
    """
    __slots__ = ('var', 'codeloc')

    def __init__(self, var, codeloc):
        self.var = var
        self.codeloc = codeloc

    def __eq__(self, other):
        return self.var == other.var and self.codeloc == other.codeloc

    def __hash__(self):
        return hash(('VarUse', self.var, self.codeloc))

    def __repr__(self):
        return '<Use of %s at %s>' % (self.var, self.codeloc)

class QualifiedLiveSet:
    __slots__ = ['uses', 'ctx']

    def __init__(self, ctx, uses=None):
        """
        :param CallString ctx:
        :param iterable uses: An iterable of `VarUse` to populate the uses set.
        """
        if uses is None:
            self.uses = set()
        else:
            self.uses = set(u for u in uses)

        self.ctx = ctx

    def can_represent(self, other):
        """ Determine whether this QualifiedVars can represent another.

        A QualifiedVars A can represent a QualifiedVars B if and only if:

        * A and B's sets of variable uses are equal, and
        * A's context is a prefix of B's.
        """
        return self.uses == other.uses and self.ctx.can_represent(other.ctx)

    def gen_uses(self, uses):
        """
        :param uses: Iterable of `VarUse`s to add to the live set.
        """
        self.uses |= set(uses)

    def kill_vars(self, vars):
        """ Kill (remove all uses of) variables from the live set.

        :param vars: Iterable of `Var`s to kill.
        """
        self.uses = set(u for u in self.uses if u.var not in vars)

    def copy(self):
        """ Get a copy of this QualifiedLiveSet. """
        return QualifiedLiveSet(self.ctx.copy(), self.uses)

    def __eq__(self, other):
        return self.uses == other.uses and self.ctx == other.ctx

    def __hash__(self):
        return hash(("QualifiedLiveSet", *sorted(list(self.uses)), self.ctx))

    def __repr__(self):
        if len(self.ctx) > 4:
            displayed_ctx = ['0x%x' % n.call_addr for n in self.ctx.stack[-4:]]
            displayed_ctx = '(..., ' + ', '.join(displayed_ctx) + ')'
        else:
            displayed_ctx = ['0x%x' % n.call_addr for n in self.ctx.stack]
            displayed_ctx = '(' + ', '.join(displayed_ctx) + ')'

        return "<QualifiedLiveSet %s %s>" % (displayed_ctx, self.uses)

class LiveVars:
    """ The per-node state of an interprocedural live variables analysis. Contains sets of live
    variables qualified with calling contexts (`QualifiedLiveSet`s). """

    __slots__ = ('arch', '_livesets', 'fn_addr', 'sp', 'bp')

    def __init__(self, arch, fn_addr, livesets=None, sp=0, bp=None):
        """ Initialize the LiveVars.

        By default, the state is initialized with a single empty set of variable uses qualified by
        an empty call string.

        :param arch: The guest architecture for the analysis.
        :param iterable livesets: An iterable of `QualifiedLiveSet` to populate the live uses set.
        :param int fn_addr: The entry address of the function associated with this LiveVars.
        :param int sp: The frame-space offset of the stack pointer. Assumed to be 0 at function
                entry and exit.
        :param (int or None) bp: The frame-space offset of the base pointer, or None if the base
                pointer has not been established for the current function (at entry and exit).
        """
        self.arch = arch
        self.fn_addr = fn_addr
        self.sp = sp
        self.bp = bp

        if livesets is None:
            self._livesets = { QualifiedLiveSet(CallString()) }
        else:
            self._livesets = set(uses)

    @property
    def livesets(self):
        return self._livesets

    def unqualified_uses(self):
        """ Aggregate all variable uses in all contexts into a single set, discarding their
        contexts.

        :rtype: set of `VarUse`
        """
        return reduce(operator.or_, (ls.uses for ls in self._livesets), set())

    def uses_of_var(self, var):
        """ Get all uses of the given variable in this LiveVars, discarding their contexts.

        :rtype: set of `VarUse`
        """
        return set(u for unqualed in self.unqualified_uses() for u in unqualed if u.var == var)

    def representative(self, liveset):
        """ Get the representative of the given QualifiedLiveSet in this LiveVars.

        Used to limit the number and length of calling contexts created by the analysis for
        recursive call cycles.

        The representative of a QualifiedLiveSet is the QualifiedLiveSet with the lexicographically
        least context among those that refer to the same set of live variable uses.

        If the given use is not in this LiveDefs, returns None.

        :param QualifiedLiveSet liveset:
        """
        return min((ls for ls in self._livesets if ls.can_represent(liveset)), \
                key=lambda ls: ls.ctx, default=None)

    def represented_by(self, liveset):
        """ Construct the set of QualifiedLiveSet with contexts that are represented by that of the
        given use.

        This method creates a set of QualifiedLiveSet whose associated live sets are the same as
        that of the given QualifiedLiveSet, and whose contexts are all those in the current LiveVars
        that can be represented by the context of the given QualifiedLiveSet.

        Returns None if no such contexts exist in this LiveVars.

        Used to regenerate elided calling contexts at the end of recursive calling sequences.

        :param QualifiedLiveSet liveset:
        """
        return set(QualifiedLiveSet(liveset.copy(), ls.ctx) for ls in self._livesets if \
                liveset.ctx.can_represent(ls.ctx))

    def gen_uses(self, uses):
        """
        :param uses: Iterable of `VarUse`s to add to all live sets.
        """
        new_livesets = set()

        for liveset in self.livesets:
            liveset.gen_uses(uses)
            new_livesets.add(liveset)

        self._livesets = new_livesets

    def kill_vars(self, vars):
        """
        :param vars: Iterable of `Var`s whose uses to remove from all live sets.
        """
        new_livesets = set()

        for liveset in self.livesets:
            liveset.kill_vars(vars)
            new_livesets.add(liveset)

        self._livesets = new_livesets

    def gen_uses_if_live(self, uses, if_live):
        """ Add `uses` to each live set that contains at least one use from `if_live`.

        :param uses: Iterable of `VarUse`
        :param if_live: Iterable of `VarUse`
        """
        new_livesets = set()

        for liveset in self.livesets:
            if len(liveset.uses & set(if_live)) > 0:
                liveset.gen_uses(uses)
            new_livesets.add(liveset)

        self._livesets = new_livesets

    @property
    def execution_ctx(self):
        """ Wrap this `LiveVars`s function address and stack frame pointers in an ExecutionCtx. """
        return ExecutionCtx(self.fn_addr, self.sp, self.bp)

    def __repr__(self):
        return 'LiveVars(%s)' % self._livesets

    def copy(self):
        """ Get a shallow copy of this LiveVars. """
        return LiveVars(self.arch, self.fn_addr, self._livesets, self.sp, self.bp)

def vars_modified(stmt, ctx, arch=None):
    """ Get the set of variables modified by the given statement.

    :param IRStmt stmt:
    :param ExecutionCtx ctx: The current execution context.
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    if type(stmt) is IRStmt.Put:
        if arch is None or stmt.offset not in (arch.sp_offset, arch.bp_offset, arch.ip_offset):
            return { Register(stmt.offset, get_type_size_bytes(stmt.data.result_type(None))) }
        else:
            return set()

    elif type(stmt) is IRStmt.Store:
        ty = stmt.data.result_type(None)
        return { memory_location(stmt.addr, ctx, arch, ty) }

    else:
        if type(stmt) not in [IRStmt.NoOp, IRStmt.AbiHint, IRStmt.IMark]:
            l.error("[vars_modified] Unimplemented for statement type %s" % type(stmt))
        return set()

def vars_used_expr(expr, ctx, arch=None):
    """ Get the set of variables whose values are used in the given expression.

    :param IRExpr stmt:
    :param ExecutionCtx ctx:
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    recurse = lambda e: vars_used_expr(e, ctx, arch)

    if type(expr) is IRExpr.Get \
            and (arch is None or expr.offset not in [arch.sp_offset, arch.bp_offset]):
        return { Register(expr.offset, get_type_size_bytes(expr.ty)) }

    elif type(expr) is IRExpr.Load:
        return { memory_location(expr.addr, ctx, arch, expr.ty) } | recurse(expr.addr)

    elif type(expr) in [IRExpr.Unop, IRExpr.Binop, IRExpr.Triop, IRExpr.Qop]:
        return reduce(operator.or_, (recurse(e) for e in expr.args))

    elif type(expr) is IRExpr.ITE:
        return recurse(expr.cond) | recurse(expr.iffalse) | recurse(expr.iftrue)

    else:
        if type(expr) is not IRExpr.Const:
            l.error("[vars_used_expr] unimplemented for expression type %s" % type(expr))
        return set()

def vars_used(stmt, ctx, arch=None):
    """ Get the set of variables whose values are used by the given statement.

    :param IRStmt stmt:
    :param ExecutionCtx ctx:
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    from_expr = lambda e: vars_used_expr(e, ctx, arch)

    if type(stmt) is IRStmt.Put:
        return from_expr(stmt.data)

    elif type(stmt) is IRStmt.Store:
        return from_expr(stmt.addr) | from_expr(stmt.data)

    elif type(stmt) is IRStmt.Exit:
        return from_expr(stmt.guard) | from_expr(stmt.dst)

    else:
        if type(stmt) not in [IRStmt.NoOp, IRStmt.AbiHint, IRStmt.IMark]:
            l.error("[vars_used] unimplemented for statement type %s" % type(stmt))
        return set()
