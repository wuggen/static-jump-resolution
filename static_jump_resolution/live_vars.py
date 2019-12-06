from angr.analyses.code_location import CodeLocation

from .atoms import Atom, Tmp, Register, RegisterOffset, MemoryLocation

import operator
import pyvex

class CtxRecord:
    """ A call record in a calling context string.

    Consists of the associated dummy call node, and the pseudo-values of the
    stack and base pointers at the time it was recorded.

    :param (CFGNode or DummyNode) node:
    :param int sp:
    :param int bp:
    """

    __slots__ = ("_node", "_sp", "_bp")

    def __init__(self, node, sp, bp):
        self._node = node
        self._sp = sp
        self._bp = bp

    @property
    def stack_ptr(self):
        return self._sp

    @property
    def base_ptr(self):
        return self._bp

    @property
    def call_node(self):
        return self._node

    @property
    def call_addr(self):
        """ The address of the call instruction associated with this record.
        """
        return self._node.call_addr

    def __eq__(self, other):
        return self._node == other._node and \
                self._sp == other._sp and \
                self._bp == other._bp

    def __hash__(self):
        return hash(("CtxRecord", self._node, self._sp, self._bp))

    def __repr__(self):
        return "<CtxRecord %s (sp %d, bp %d)>" % (self._node, self._sp, self._bp)

class CallString:
    """ A full calling context. Essentially a stack of CtxRecords.

    :param records: (Optional) An iterable of CtxRecord containing the initial
        stack contents, from bottom to top. If not given, the stack is
        initially empty.
    """

    __slots__ = ('_records',)

    def __init__(self, records=None):
        if records is None:
            self._records = []
        else:
            self._records = [c for c in records]

    @property
    def top(self):
        if len(self._records) == 0:
            return None
        else:
            return self._records[-1]

    def push(self, record):
        self._records.append(record)

    def pop(self):
        return self._records.pop()

    @property
    def stack(self):
        return [n for n in self._records]

    def __eq__(self, other):
        if len(self._records) != len(other._records):
            return False

        for (n, m) in zip(self._records, other._records):
            if n != m:
                return False

        return True

    def __lt__(self, other):
        if len(self._records) < len(other._records):
            return True
        elif len(self._records) > len(other._records):
            return False

        for (n, m) in zip(self._records, other._records):
            if n.call_addr < m.call_addr:
                return True
            elif n.call_addr > m.call_addr:
                return False

        return False

    def __le__(self, other):
        if len(self._records) < len(other._records):
            return True
        elif len(self._records) > len(other._records):
            return False

        for (n, m) in zip(self._records, other._records):
            if n.call_addr < m.call_addr:
                return True
            elif n.call_addr > m.call_addr:
                return False

        return True

    def __gt__(self, other):
        return other < self

    def __ge__(self, other):
        return other <= self

    def __ne__(self, other):
        return not (self == other)

    def can_represent(self, other):
        """ Determine whether this CallString can be a representative of
        another.

        A call string A can represent a call string B if and only if A is a
        prefix of B.
        """
        if len(other._records) < len(self._records):
            return False

        for (n, m) in zip(self._records, other._records):
            if n != m:
                return False

        return True

    def __hash__(self):
        return hash(("CallString", tuple(self._records)))

    def __len__(self):
        return len(self._records)

    def __repr__(self):
        pass

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
        * A and B refer to the same definition, and
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
        """ Get the representative of the given use in this LiveVars.

        The representative of a qualified use is the qualified use with
        shortest context among those that refer to the same use. Ties among
        same-length contexts are broken by lexicographic ordering of call site
        addresses.

        If the given use is not in the LiveDefs, returns None.
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
