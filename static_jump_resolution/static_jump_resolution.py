from angr.analyses.analysis import Analysis
from angr.analyses.forward_analysis import ForwardAnalysis

from .engine import SimEngineSJRVEX
from .live_definitions import LiveDefinitions
from .supergraph import SupergraphVisitor, DummyNode

import logging
import operator
import functools

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)

class StaticJumpResolutionAnalysis(ForwardAnalysis, Analysis):
    def __init__(self, cfg, status_callback=None, graph_visitor=None):
        if graph_visitor is None:
            graph_visitor = SupergraphVisitor(cfg)
        elif type(graph_visitor) is not SupergraphVisitor:
            raise TypeError('StaticJumpResolution needs a SupergraphVisitor')

        ForwardAnalysis.__init__(self, status_callback=status_callback, graph_visitor=graph_visitor)

        self._engine = SimEngineSJRVEX()

        l.info('Finished initialization.\nGraph nodes: {}\nGraph edges: {}'.format(
            len(graph_visitor.graph), graph_visitor.graph.size()))

        self._analyze()

    def results_by_function(self, fn_addr):
        states = {n: s for (n, s) in self._state_map.items() if n.function_address == fn_addr}
        return states

    def _pre_analysis(self):
        pass

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

    def _initial_abstract_state(self, node):
        return LiveDefinitions(self.project.arch)

    def _run_on_node(self, node, state):
        state = state.copy()

        if type(node) is not DummyNode and not node.is_simprocedure:
            state = self._engine.process(state, block=node.block)

        return None, state

    def _merge_states(self, node, *states):
        l.info('Called _merge_states(%s, %s)' % \
                (node, '[' + ', '.join(str(s) for s in states) + ']'))

        state0 = self._state_map.get(node, LiveDefinitions(self.project.arch))
        merged = functools.reduce(operator.or_,
                (s for s in states if s is not None),
                LiveDefinitions(self.project.arch))

        if merged == state0:
            # Reached fixpoint
            return state0, True
        else:
            # Still more to go
            return merged, False

from angr.analyses import register_analysis
register_analysis(StaticJumpResolutionAnalysis, 'StaticJumpResolutionAnalysis')
