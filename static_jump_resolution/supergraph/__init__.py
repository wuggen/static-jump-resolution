from angr.analyses.forward_analysis.visitors.graph import GraphVisitor
from angr.analyses.forward_analysis.visitors.call_graph import CallGraphVisitor
from angr.knowledge_plugins.functions import Function
from angr.analyses.cfg.cfg_utils import CFGUtils

from .supergraph import supergraph_from_cfg, DummyNode

import pyvex

class SupergraphVisitor(GraphVisitor):
    """ A GraphVisitor for whole-program, interprocedural analysis.

    Constructs and visits an interprocedural supergraph from the given CFG analysis.  The CFG should
    contain a graph of as much of the binary as possible; at minimum, it should contain the entry
    function of the program and each function reachable via direct calls.

    `SupergraphVisitor` constructs a supergraph using the `supergraph_from_cfg()` function, which
    has the side effect of normalizing the CFG and all function transition graphs in the associated
    knowledge base. Additionally, the resulting graph contains dummy call and return nodes (of type
    `DummyNode`) to simplify certain analyses. These dummy nodes are not hidden by
    `SupergraphVisitor` and are part if its interface. See the documentation for
    `supergraph_from_cfg()` for further details.

    :param cfg: A CFG analysis object for the current binary.
    """

    def __init__(self, cfg):
        super(SupergraphVisitor, self).__init__()
        self._cfg = cfg
        self._supergraph = supergraph_from_cfg(cfg)
        self._functions = cfg.functions
        self.reset()

    def startpoints(self):
        """ Get all entry nodes of the program.

        :return: A list of CFGNode or DummyNode.
        """

        # entry nodes of all functions
        start_nodes = [self._cfg.model.get_node(f.addr) for f in self._functions]

        # only those entry nodes with no incoming call edges
        start_nodes = filter(
                lambda n: len(self._cfg.model.get_predecessors(n, jumpkind='Ijk_Call')) == 0,
                start_nodes)

        return start_nodes

    def successors(self, node, context=None):
        """ Get the successors of the given node.

        `context` should be `None` or the most recently traversed Call node.
        
        If the context is `None`, or if the current node does not end in a return, get all
        successors of the current node in the supergraph.

        If the context is a Call node and the current node ends in a return, get a singleton list
        containing the successor of this node that corresponds to returning from the call specified
        by the context. If such a successor does not exist, return an empty list.

        :param ISRB or DummyNode node: The current node.
        :param DummyNode context:      (Optional) The current calling context.
        :return:                       A list of CFGNode or DummyNode
        """
        succs = self._supergraph.successors(node)

        if context is None or type(node) is DummyNode:
            return succs
        elif type(context) is DummyNode:
            if context.dummy_type is not 'Dummy_Call':
                raise ValueError("Expected 'Dummy_Call' node, got '{}'".format(context.dummy_type))

            if node.has_return:
                succs = filter(
                            lambda s: type(s) is DummyNode and s.parent_block is context.parent_block,
                            succs
                        )

            return succs
        else:
            raise TypeError("context should be None or DummyNode, got '{}'".format(type(context)))

    def predecessors(self, node, context=None):
        """ Get the predecessors of the given node.

        `context` should be `None`, or the most recently traversed Call node.

        If the context is `None`, get all predecessors of the current node in the supergraph.

        If the context is a Call node, get all predecessors of the current node within the same
        function, and the given Call node if it is a predecessor.

        :param ISRB or DummyNode node: The current node.
        :param DummyNode context:      (Optional) The current calling context.
        :return:                       A list of CFGNode or DummyNode
        """
        preds = self._supergraph.get_predecessors(node)

        if context is None or type(node) is DummyNode:
            return preds
        elif type(context) is DummyNode:
            if context.dummy_type is not 'Dummy_Call':
                raise ValueError("Expected 'Dummy_Call' node, got '{}'".format(context.dummy_type))

            preds = filter(lambda n: type(n) is not DummyNode or n is context, preds)
            return preds

    def sort_nodes(self, nodes=None):
        """ Get the nodes of the supergraph sorted in reverse-post-order.

        If `nodes` is `None`, return all nodes of the graph. If `nodes` is an iterable of
        `CFGNode`s, return the subsequence of the sorted graph containing those nodes.

        :param iterable nodes: (Optional) A subset of the graph's nodes.
        :return:               A list of nodes sorted in reverse-post-order.
        :rtype:                list
        """
        rpo = CFGUtils.reverse_post_order_sort_nodes(self._supergraph)

        if nodes is not None:
            nodes = set(nodes)
            rpo = [n for n in rpo if n in nodes]

        return rpo

    @property
    def graph(self):
        """ Get the supergraph in use by this SupergraphVisitor.

        :return: The underlying supergraph.
        :rtype:  networkx.DiGraph
        """
        return self._supergraph
