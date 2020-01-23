class CtxRecord:
    """ A call record in a calling context string.

    Consists of the associated dummy call node, and the pseudo-values of the
    stack and base pointers at the time it was recorded.

    :param DummyNode node:
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
        """ The value of the stack pointer associated with this record. """
        return self._sp

    @property
    def base_ptr(self):
        """ The value of the base pointer associated with this record. """
        return self._bp

    @property
    def call_node(self):
        """ The dummy call node associated with this record. """
        return self._node

    @property
    def call_addr(self):
        """ The address of the call instruction associated with this record.  """
        return self._node.call_addr

    def __eq__(self, other):
        """ For the purposes of equality testing, the values of the stack and base pointers are
        ignored. """
        return self._node == other._node

    def __hash__(self):
        """ For the purposes of hashing, the values of the stack and base pointers are ignored. """
        return hash(("CtxRecord", self._node))

    def __repr__(self):
        return "<CtxRecord 0x%x (sp=%d, bp=%d)>" % (self._node.call_addr, self._sp, self._bp)

class CallString:
    """ A full calling context. Essentially a stack of CtxRecords.

    CallStrings are ordered lexicographically based on the call site address of each record.

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
        """ The top (most recent) call record. """
        if len(self._records) == 0:
            return None
        else:
            return self._records[-1]

    def push(self, record):
        """ Add a call record to the string. """
        self._records.append(record)

    def pop(self):
        """ Remove and return the top (most recent) call record. """
        return self._records.pop()

    @property
    def stack(self):
        """ A shallow copy of the internal record list, most recent call last. """
        return [n for n in self._records]

    def __eq__(self, other):
        if len(self._records) != len(other._records):
            return False

        for (n, m) in zip(self._records, other._records):
            if n != m:
                return False

        return True

    def __lt__(self, other):
        for (n, m) in zip(self._records, other._records):
            if n.call_addr < m.call_addr:
                return True
            elif n.call_addr > m.call_addr:
                return False

        if len(self._records) < len(other._records):
            return True
        elif len(self._records) > len(other._records):
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
        if len(self._records) > 3:
            prefix = " ... "
            records = self._records[-3:]
        else:
            prefix = ""
            records = self._records

        return "<CallString [" ++ prefix ++ ", ".join([r.__repr__() for r in records]) ++ "]>"

class ExecutionCtx:
    """ An execution context, consisting of the currently executing function, a call string, and
    current values of the stack and base pointers.
    """
    def __init__(self, fn, sp, bp, callstring):
        self._fn = fn
        self._sp = sp
        self._bp = bp
        self._callstring = callstring

    @property
    def fn(self):
        return self._fn

    @property
    def stack_ptr(self):
        return self._sp

    @property
    def base_ptr(self):
        return self._bp

    @property
    def callstring(self):
        return self._callstring

    def __eq__(self, other):
        return self._fn.addr == other._fn.addr \
            and self._sp == other._sp \
            and self._bp == other._bp \
            and self._callstring == other._callstring

    def __repr__(self):
        return "<ExecutionCtx [%d] 0x%x sp=%d bp=%d>" \
                % (len(self._callstring), self._fn.addr, self._sp, self._bp)
