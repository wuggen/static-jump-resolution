from angr.analyses.code_location import CodeLocation

from .atoms import Atom, Tmp, Register, RegisterOffset, MemoryLocation

import operator
import pyvex

class Definition:
    """
    :param Atom atom:
    :param CodeLocation codeloc:
    """
    __slots__ = ('atom', 'codeloc')

    def __init__(self, atom, codeloc):
        self.atom = atom
        self.codeloc = codeloc

    def __eq__(self, other):
        return self.atom == other.atom and self.codeloc == other.codeloc

    def __hash__(self):
        return hash(('Definition', self.atom, self.codeloc))

    def __repr__(self):
        return '<Definition of %s at %s>' % (self.atom, self.codeloc)

class LiveDefinitions:
    __slots__ = ('_defs', 'arch')

    def __init__(self, arch, defs=None):
        """
        :param arch: The guest architecture.
        :param iterable defs: An iterable of `Definition` to populate the live defs set.
        """
        self.arch = arch

        if defs is None:
            self._defs = set()
        else:
            self._defs = set(defs)

    def kill_defs(self, *atoms):
        """
        :param Atom[, ... ] atoms: Atoms whose definitions will be killed (removed from the live
                set).
        """
        self._defs = set(d for d in self._defs if d.atom not in atoms)

    def gen_defs(self, *defs):
        """
        :param *Definition defs: Definitions to add to the live set.
        """
        self._defs |= set(defs)

    def kill_and_gen_defs(self, *defs):
        """ Add defs and kill conflicting defs.

        Kills all definitions of atoms modified by the given defs, then adds the given defs.

        :param *Definition defs: Definitions with which to update the live set.
        """
        self.kill_defs(*(d.atom for d in defs))
        self.gen_defs(*defs)

    def __repr__(self):
        return 'LiveDefinitions(%s)' % self._defs

    def __len__(self):
        return len(self._defs)

    def __iter__(self):
        return iter(self._defs)

    def __contains__(self, item):
        return item in self._defs

    def _binop(self, other, op):
        import logging
        l = logging.getLogger(__name__)
        l.setLevel(logging.DEBUG)
        l.debug('LiveDefinitions._binop, type(other) = %s' % type(other))
        if type(other) is LiveDefinitions:
            return op(self._defs, other._defs)
        else:
            raise NotImplementedError

    def __and__(self, other):
        return LiveDefinitions(self.arch, self._binop(other, operator.and_))

    def __or__(self, other):
        return LiveDefinitions(self.arch, self._binop(other, operator.or_))

    def __xor__(self, other):
        return LiveDefinitions(self.arch, self._binop(other, operator.xor))

    def __sub__(self, other):
        return LiveDefinitions(self.arch, self._binop(other, operator.or_))

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
        self._defs = self._binop(other, operator.iand)
        return self

    def __ior__(self, other):
        self._defs = self._binop(other, operator.ior)
        return self

    def __ixor__(self, other):
        self._defs = self._binop(other, operator.ixor)
        return self

    def __isub__(self, other):
        self._defs = self._binop(other, operator.isub)
        return self

    def copy(self):
        return LiveDefinitions(self.arch, self._defs.copy())
