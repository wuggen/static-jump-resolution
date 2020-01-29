from angr.analyses.code_location import CodeLocation

from .context import CtxRecord, CallString
from .vars import Var, Register, StackVar, MemoryLocation, memory_location, get_type_size_bytes

import operator
from functools import reduce

import pyvex
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

class QualifiedUse:
    """ A use qualified with a calling context.

    :param VarUse use:
    :param CallString ctx:
    """

    __slots__ = ('use', 'ctx')

    def __init__(self, use, ctx):
        self.use = use
        self.ctx = ctx

    def can_represent(self, other):
        """ Determine whether this QualifiedUse can represent another.

        A QualifiedUse A can represent a QualifiedUse B if and only if:
        * A and B refer to the same variable use, and
        * A's context is a prefix of B's.
        """
        return self.use == other.use and self.ctx.can_represent(other.ctx)

    def __eq__(self, other):
        return self.use == other.use and self.ctx == other.ctx

    def __hash__(self):
        return hash(("QualifiedUse", self.use, self.ctx))

    def __repr__(self):
        if len(self.ctx) > 4:
            displayed_ctx = ['0x%x' % n.call_addr for n in self.ctx.stack[-4:len(self.ctx)]]
            displayed_ctx = '( ... , ' + ', '.join(displayed_ctx) + ')'
        else:
            displayed_ctx = ['0x%x' % n.call_addr for n in self.ctx.stack]
            displayed_ctx = '(' + ', '.join(displayed_ctx) + ')'

        return '<QualifiedUse %s %s>' % (displayed_ctx, self.use)

class LiveVars:
    __slots__ = ('_uses', 'arch')

    def __init__(self, arch, uses=None):
        """
        :param arch: The guest architecture.
        :param iterable uses: An iterable of `QualifiedUse` to populate the
            live uses set.
        """
        self.arch = arch

        if uses is None:
            self._uses = set()
        else:
            self._uses = set(uses)

    def uses_of_var(self, var):
        """ Get all qualified uses of the given variable in this LiveVars. """
        return set(u for u in self._uses if u.var == var)

    def representative(self, use):
        """ Get the representative of the given qualified use in this LiveVars.

        The representative of a qualified use is the qualified use with
        shortest context among those that refer to the same use. Ties among
        same-length contexts are broken by lexicographic ordering of call site
        addresses.

        If the given use is not in the LiveDefs, returns None.

        :param QualifiedUse use:
        """
        return min((u for u in self._uses if u.can_represent(use)), key=lambda u: u.ctx, default=None)

    def represented_by(self, use):
        """ Construct the set of qualified uses with contexts that are
        represented by that of the given use.

        This method creates a set of QualifiedUse whose associated uses are the
        same as that of the given use, and whose contexts are all those in the
        current LiveVars that can be represented by the context of the given
        use.

        Returns None if no such contexts exist in this LiveVars.

        :param QualifiedUse use:
        """
        return set(QualifiedUse(use.use, u.ctx) for u in self._uses if use.ctx.can_represent(u.ctx))

    def kill_vars(self, *vars):
        """
        :param *Var vars: Vars to be killed (their uses removed from the live
            set).
        """
        vars = set(vars)
        self._uses = set(u for u in self._uses if u.use.var not in vars)

    def gen_uses(self, *uses):
        """
        :param *QualifiedUse uses: VarUses to add to the live set.
        """
        self._uses |= set(uses)

    def __repr__(self):
        return 'LiveUses(%s)' % self._uses

    def __len__(self):
        return len(self._uses)

    def __iter__(self):
        return iter(self._uses)

    def __contains__(self, item):
        return item in self._uses

    def _binop(self, other, op):
        import logging
        l = logging.getLogger(__name__)
        l.setLevel(logging.DEBUG)
        l.debug('LiveUses._binop, type(other) = %s' % type(other))
        if type(other) is LiveUses:
            return op(self._uses, other._uses)
        else:
            raise NotImplementedError

    def __and__(self, other):
        return LiveUses(self.arch, self._binop(other, operator.and_))

    def __or__(self, other):
        return LiveUses(self.arch, self._binop(other, operator.or_))

    def __xor__(self, other):
        return LiveUses(self.arch, self._binop(other, operator.xor))

    def __sub__(self, other):
        return LiveUses(self.arch, self._binop(other, operator.or_))

    def __le__(self, other):
        return self._binop(other, operator.le)

    def __lt__(self, other):
        return self._binop(other, operator.lt)

    def __ge__(self, other):
        return self._binop(other, operator.ge)

    def __gt__(self, other):
        return self._binop(other, operator.gt)

    def __eq__(self, other):
        return self._binop(other, operator.eq)

    def __iand__(self, other):
        self._uses = self._binop(other, operator.iand)
        return self

    def __ior__(self, other):
        self._uses = self._binop(other, operator.ior)
        return self

    def __ixor__(self, other):
        self._uses = self._binop(other, operator.ixor)
        return self

    def __isub__(self, other):
        self._uses = self._binop(other, operator.isub)
        return self

    def __iter__(self):
        return self._uses.__iter__()

    def copy(self):
        """ Get a shallow copy of this LiveUses. """
        return LiveUses(self.arch, self._uses.copy())

def vars_modified(stmt, ctx, arch=None):
    """ Get the set of variables modified by the given statement.

    :param IRStmt stmt:
    :param ExecutionCtx ctx: The current execution context.
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    if type(stmt) is pyvex.IRStmt.Put:
        if arch is None or stmt.offset not in (arch.sp_offset, arch.bp_offset, arch.ip_offset):
            return { Register(stmt.offset, get_type_size_bytes(stmt.data.result_type(None))) }
        else:
            return set()

    elif type(stmt) is pyvex.IRStmt.Store:
        ty = stmt.data.result_type(None)
        return { memory_location(stmt.addr, ctx, arch, ty) }

    else:
        l.warning("[vars_modified] Unimplemented for statement type %s" % type(stmt))
        return set()

def vars_used_expr(expr, ctx, arch=None):
    """ Get the set of variables whose values are used in the given expression.

    :param IRExpr stmt:
    :param ExecutionCtx ctx:
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    recurse = lambda e: vars_used_expr(e, ctx, arch)

    if type(expr) is pyvex.IRExpr.Get \
            and expr.offset not in [arch.sp_offset, arch.bp_offset]:
        return { Register(expr.offset, get_type_size_bytes(expr.ty)) }

    elif type(expr) is pyvex.IRExpr.Load:
        return { memory_location(expr.addr, ctx, arch, expr.ty) } | recurse(expr.addr)

    elif type(expr) in [pyvex.IRExpr.Unop, pyvex.IRExpr.Binop, pyvex.IRExpr.Triop, pyvex.IRExpr.Qop]:
        return reduce(operator.or_, (recurse(e) for e in expr.args))

    elif type(expr) is pyvex.IRExpr.ITE:
        return recurse(expr.cond) | recurse(expr.iffalse) | recurse(expr.iftrue)

    else:
        return set()

def vars_used(stmt, ctx, arch=None):
    """ Get the set of variables whose values are used by the given statement.

    :param IRStmt stmt:
    :param ExecutionCtx ctx:
    :param Arch arch: The guest architecture. If provided, used to create more accurate results.
    :rtype: Iterable of Var
    """
    from_expr = lambda e: vars_used_expr(e, ctx, arch)

    if type(stmt) is pyvex.IRStmt.Put:
        return from_expr(stmt.data)

    elif type(stmt) is pyvex.IRStmt.Store:
        return from_expr(stmt.addr) | from_expr(stmt.data)

    else:
        l.warning("[vars_used] unimplemented for statement type %s" % type(stmt))
        return set()
