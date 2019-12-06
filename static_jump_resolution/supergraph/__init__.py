from angr.analyses.forward_analysis.visitors.graph import GraphVisitor
from angr.analyses.forward_analysis.visitors.call_graph import CallGraphVisitor
from angr.knowledge_plugins.functions import Function
from angr.analyses.cfg.cfg_utils import CFGUtils

from .supergraph import supergraph_from_cfg, DummyNode

import pyvex

def node_is_entry(node):
    """ Is a node the entry node of its function?

    :param (CFGNode or DummyNode) node:
    """
    return type(node) is CFGNode and node.function_address == node.addr

def node_is_exit(node):
    """ Is a node an exit node of its function?

    :param (CFGNode or DummyNode) node:
    """
    return type(node) is CFGNode and node.has_return

def node_is_call(node):
    """ Is a node a dummy call node?

    :param (CFGNode or DummyNode) node:
    """
    return type(node) is DummyNode and node.dummy_type == 'Dummy_Call'

def node_is_ret(node):
    """ Is a node a dummy return node?

    :param (CFGNode or DummyNode) node:
    """
    return type(node) is DummyNode and node.dummy_type == 'Dummy_Ret'

class Worklist:
    """ An intraprocedurally eager worklist.

    :param str direction: 'forward' (default) or 'backward'.
    :param iterable nodes: Initial nodes to add to the worklist.
    """
    __slots__ = ['_direction', '_intra_list', '_fn_boundary_list', '_call_list', '_ret_list']

    def __init__(self, direction='forward', nodes=None):
        self._direction = direction
        self.clear()

        if nodes is not None:
            for n in nodes:
                self.add(n)

    def clear(self):
        """ Clear the worklist. """

        # Worklists. A node is taken from a particular list only if all the preceding
        # lists are empty.
        #
        # `_intra_list` contains intraprocedural nodes and function entry nodes if
        # in forward flow mode, function exit nodes if in backward flow mode.
        #
        # `_fn_boundary_list` contains function exit nodes if in forward flow mode,
        # function entry nodes if in backward flow mode.
        #
        # `_call_list` contains call nodes, and takes precedence over `_ret_list` when
        # in forward flow mode.
        #
        # `_ret_list` contains return nodes, and takes precedence over `_call_list` when
        # in backward flow mode.
        self._intra_list = []
        self._fn_boundary_list = []
        self._call_list = []
        self._ret_list = []

    def add(self, node):
        """ Add a node to the worklist.

        :param (CFGNode or DummyNode) node:
        """
        if node_is_entry(n):
            if self._direction == 'forward':
                self._intra_list.append(n)
            else:
                self._fn_boundary_list.append(n)
        elif node_is_exit(n):
            if self._direction == 'forward':
                self._fn_boundary_list.append(n)
            else:
                self._intra_list.append(n)
        elif node_is_call(n):
            self._call_list.append(n)
        elif node_is_ret(n):
            self._ret_list.append(n)
        else:
            self._intra_list.append(n)

    def next_node(self):
        """ Remove and return the next node in the worklist.

        Returns `None` if the worklist is empty.
        """
        if len(self._intra_list) > 0:
            return self._intra_list.pop()
        elif len(self._fn_boundary_list) > 0:
            return self._fn_boundary_list.pop()

        if self._direction == 'forward':
            if len(self._call_list) > 0:
                return self._call_list.pop()
            elif len(self._ret_list) > 0:
                return self._ret_list.pop()
        else:
            if len(self._ret_list) > 0:
                return self._ret_list.pop()
            elif len(self._call_list) > 0:
                return self._call_list.pop()

        return None

    def copy(self):
        """ Get a new `Worklist` instance that is a (shallow) copy of this one. """
        newlist = Worklist(self._direction)
        newlist._intra_list = [n for n in self._intra_list]
        newlist._fn_boundary_list = [n for n in self._fn_boundary_list]
        newlist._call_list = [n for n in self._call_list]
        newlist._ret_list = [n for n in self._ret_list]

        return newlist

    def empty(self):
        """ Is this worklist empty? """
        return len(self) == 0

    def has_next(self):
        """ Is this worklist non-empty? """
        return len(self) > 0

    def exhaust(self, supergraph):
        """ An iterator over all nodes reachable from the current worklist.

        The returned iterator simulates the effect of repeatedly taking the
        next node from the worklist and adding each of its traversal
        successors. Each node is visited at most once; any node that has
        already been visited since iteration began is not re-added to the
        worklist.

        The given supergraph is used to determine traversal successors for each
        node.

        :param networkx.DiGraph supergraph: A graph of (CFGNode or DummyNode)
        """
        visited = set()
        while self.has_next():
            n = self.next()
            if self._direction == "forward":
                succs = supergraph.get_successors(n)
            else:
                succs = supergraph.get_predecessors(n)

            for s in succs:
                if s not in visited:
                    visited.add(s)
                    self.add(s)

            yield n

    def __len__(self):
        return len(self._intra_list) \
                + len(self._fn_boundary_list) \
                + len(self._call_list) \
                + len(self._ret_list)

    def __iter__(self):
        wl = self.copy()
        while len(wl) > 0:
            yield wl.next()

class SupergraphVisitor(GraphVisitor):
    """ A GraphVisitor for whole-program, interprocedural analysis.

    Constructs and visits an interprocedural supergraph from the given CFG
    analysis.  The CFG should contain a graph of as much of the binary as
    possible; at minimum, it should contain the entry function of the program
    and each function reachable via direct calls.

    `SupergraphVisitor` constructs a supergraph using the
    `supergraph_from_cfg()` function, which has the side effect of normalizing
    the CFG and all function transition graphs in the associated knowledge
    base. Additionally, the resulting graph contains dummy call and return
    nodes (of type `DummyNode`) to simplify certain analyses. These dummy nodes
    are not hidden by `SupergraphVisitor` and are part if its interface. See
    the documentation for `supergraph_from_cfg()` for further details.

    `SupergraphVisitor` implements an intraprocedurally eager traversal order,
    in which all reachable nodes of a function are visited before that
    function's callees. That is, successor nodes which are within the same
    function take precedence over call and return dummy nodes.

    A `SupergraphVisitor` can be instantiated for either forward or backward
    flow traversal. In forward flow, graph sources are visited first, call
    nodes take precedence over return nodes, and function entries take
    precedence over exits. In backward flow, graph sinks are visited first,
    return nodes take precedence over call nodes, and function exits take
    precedence over function entries.

    :param cfg: A CFG analysis object for the current binary.
    :param str direction: The direction of traversal, either 'forward'
        (default) or 'backward'.
    """

    def __init__(self, cfg, direction='forward'):
        if type(direction) is not str:
            raise TypeError
        if direction not in ('forward', 'backward'):
            raise ValueError

        self._cfg = cfg
        self._direction = direction
        self._supergraph = supergraph_from_cfg(cfg)
        self._worklist = Worklist(self._direction)

        self.reset()

    def _find_startpoints(self):
        """ Find the start points in the supergraph. """
        if self._direction == "forward":
            self._find_entry_points()
        else:
            self._find_exit_points()

    def _find_entry_points(self):
        # Try to find a main function and return its entry node
        for fn in self._cfg.functions.values():
            if fn.name == 'main':
                return [self._cfg.model.get_node(fn.addr)]

        # Fallback: all entry blocks of all functions that have no incoming call edges
        fn_entries = [self._cfg.model.get_node(fn.addr) for fn in self._cfg.functions.values()]
        entries = [n for n in fn_starts if len(self._cfg.model.get_predecessors(n, jumpkind='Ijk_Call')) == 0]

        if len(entries) > 0:
            return entries
        else:
            #Fallback fallback: all function start nodes
            return fn_entries

    def _find_exit_points(self):
        # Try to find a main function and return its exit node(s)
        for fn in self._cfg.functions.values():
            if fn.name == 'main':
                return [n for n in self._cfg.model.nodes() if n.function_address == fn.addr and n.has_return]

        # Fallback: all nodes with no successors
        exits = [n for n in self._cfg.model.nodes() if len(n.successors) == 0]
        if len(exits) > 0:
            return exits
        else:
            # Fallback fallback: all nodes with a return
            return [n for in in self._cfg.model.nodes() if n.has_return]

    def reset(self):
        self._worklist.clear()
        for n in self.startpoints():
            self._worklist.add(n)

    def startpoints(self):
        """ A list of all start points in the program.

        In forward flow mode, this is a list of all entry points of the
        program, while in backward flow mode, it is a list of all exit points
        of the program.

        :return: A list of CFGNode or DummyNode.
        """
        return [n for n in self._start_points]

    def successors(self, node):
        """ A list of the traversal successors of the given node.

        In forward flow mode, these are the graph successors of the node, while
        in backward flow mode, they are the graph predecessors.

        :param (CFGNode or DummyNode) node: The current node.
        :return: An iterator over (CFGNode or DummyNode)
        """
        if self._direction == "forward":
            return [n for n in self._supergraph.successors(node)]
        else:
            return [n for n in self._supergraph.predecessors(node)]

    def predecessors(self, node):
        """ A list of the traversal predecessors of the given node.

        In forward flow mode, these are the graph predecessors of the node,
        whilc in backward flow mode, they are the graph successors.

        :param (CFGNode or DummyNode) node: The current node.
        :return: An iterator over CFGNode or DummyNode
        """
        if self._direction == "forward":
            return [n for n in self._supergraph.get_predecessors(node)]
        else:
            return [n for n in self._supergraph.get_successors(node)]

    def sort_nodes(self, nodes=None):
        """ A sorted list of the nodes of the supergraph.

        This is equivalent to the order in which nodes would be yielded from
        `self.next_node()` if all traversal successors of each yielded node
        were added to the work list, without revisiting nodes.

        If `nodes` is `None`, return all nodes of the graph reachable from the
        start point(s). If `nodes` is an iterable of `CFGNode`s, return the
        subsequence of the sorted graph containing those nodes.

        :param iterable nodes: (Optional) A subset of the graph's nodes
        :return: A list of (CFGNode or DummyNode)
        :rtype: list
        """
        wl = Worklist(self.startpoints())
        if nodes is None:
            return [n for n in wl.exhaust(self._supergraph)]
        else:
            nodes = set(nodes)
            return [n for n in wl.exhaust(self._supergraph) if n in nodes]

    @property
    def graph(self):
        """ Get the supergraph in use by this SupergraphVisitor.

        :return: The underlying supergraph.
        :rtype:  networkx.DiGraph
        """
        return self._supergraph
