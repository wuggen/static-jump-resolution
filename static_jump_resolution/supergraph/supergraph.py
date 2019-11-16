import networkx as nx

from enum import Enum, auto

class DummyNode:
    """ A dummy node in a supergraph, representing a call to or return from a procedure.

    :param int parent_block: The parent (calling) block.
    :param str dummy_type:   The type (either 'Dummy_Call' or 'Dummy_Ret') of this dummy node.
    """

    __slots__ = ['_parent_block', '_dummy_type']

    def __init__(self, parent_block, dummy_type):
        self._parent_block = parent_block

        if dummy_type not in ('Dummy_Call', 'Dummy_Ret'):
            raise ValueError("Expected 'Dummy_Call' or 'Dummy_Ret'")

        self._dummy_type = dummy_type

    @property
    def parent_block(self):
        return self._parent_block

    @property
    def dummy_type(self):
        return self._dummy_type

    def __eq__(self, other):
        return type(other) is CallNode and \
                self.parent_block == other.parent_block and \
                self.dummy_type is other.dummy_type

    def __hash__(self):
        hash(('DummyNode', self.parent_block, self.dummy_type))

def supergraph_from_cfg(cfg):
    """ Construct a supergraph from a CFG analysis.

    In order for the supergraph to be accurate, the input CFG analysis should contain graphs for
    every known function in the current binary. If the CFG is not already normalized, it will be
    made so before constructing the supergraph. Similarly, the function transition graphs in the
    project's knowledge base will be normalized.

    The returned graph contains all nodes from the CFG. Edges in the CFG whose parent nodes do not
    end in a procedure call are also included. Procedure calls are handled as follows:

    * Any edges with jumpkind `'Ijk_FakeRet'` are ignored.
    * Empty Call and Return nodes are added, of type `DummyNode`.
    * An edge is added from the original calling node to the dummy Call node.
    * An edge is added from the Call node to the entry node of all known target procedures.
    * Edges are added from each returning node of the called procedure to the Return node.
    * Edges are added from the Return node to each original successor of the original calling node.

    The `jumpkind` attributes on the edges to Call nodes and from Ret nodes are set to
    `'Ijk_Boring'`. The edges from Call nodes have jumpkind `'Ijk_Call'`, and the edges to Ret nodes
    have jumpkind `'Ijk_Ret'`.

    Note that the above rules imply that, if the input CFG has not attempted to resolve indirect
    jumps, then all indirect jumps encountered will result in a gap in the supergraph; no edges will
    emerge from the dummy call node, since no call targets are known. Int theory, if the resulting
    supergraph is being used by a `StaticJumpResolver` analysis, then this should not be a problem,
    since the indirect jumps will be resolved anyway.

    :param cfg: The input CFG analysis.
    :return:    A supergraph of the program.
    :rtype:     networkx.DiGraph
    """

    # normalize input graphs
    if not cfg.normalized:
        cfg.normalize()

    functions = cfg.kb.functions
    for fn in functions.values():
        if not fn.normalized:
            fn.normalize()

    # collect nodes
    supergraph = nx.DiGraph()
    supergraph.add_nodes_from(cfg.graph)

    # collect function return nodes for reference
    fn_rets = {}
    for n in supergraph.nodes:
        addr = n.function_address
        if addr not in fn_rets:
            fn_rets[addr] = []

        if n.has_return or n.is_simprocedure:
            fn_rets[addr].append(n)

    # add edges
    for n in supergraph.nodes:
        # simprocedures are handled implicitly during call/return edge creation
        if n.is_simprocedure:
            continue

        vex = n.block.vex

        if vex.jumpkind is 'Ijk_Call':
            # create dummy nodes
            callnode = DummyNode(n, 'Dummy_Call')
            retnode = DummyNode(n, 'Dummy_Ret')
            supergraph.add_nodes_from((callnode, retnode))

            # get call and return targets
            call_targets = cfg.model.get_successors(n, jumpkind='Ijk_Call')
            ret_targets = cfg.model.get_successors(n, excluding_fakeret=False, jumpkind='Ijk_FakeRet')

            # add edges
            supergraph.add_edge(n, callnode, jumpkind='Ijk_Boring')

            for r in ret_targets:
                supergraph.add_edge(retnode, r, jumpkind='Ijk_Boring')

            for t in call_targets:
                supergraph.add_edge(callnode, t, jumpkind='Ijk_Call')

            for r in fn_rets[n.function_address]:
                supergraph.add_edge(r, retnode, jumpkind='Ijk_Ret')

        # for non-call edges, simply copy over the old jumpkind
        else:
            successors = cfg.model.get_successors_and_jumpkind(n)
            for s, jk in successors:
                supergraph.add_edge(n, s, jumpkind=jk)

    return supergraph
