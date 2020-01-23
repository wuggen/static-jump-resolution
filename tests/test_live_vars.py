import nose
import nose.tools as nt

from mock_nodes import *

import angr
from angr.analyses.code_location import CodeLocation

from static_jump_resolution.context import CallString

def qualified_use_represent():
    nodes = arbitrary_call_nodes(2)
    vars = arbitrary_vars(2)
    uses = arbitrary_var_uses(vars, 1)

    cs1 = CallString(nodes[:1])
    cs2 = CallString(nodes)

    quse1 = QualifiedUse(uses[vars[0]][0], cs1)
    quse2 = QualifiedUse(uses[vars[0]][0], cs2)
    nt.ok_(quse1.can_represent(quse2))
    nt.ok_(not quse2.can_represent(quse1))

    quse1 = QualifiedUse(uses[vars[1]][0], cs1)
    nt.ok_(not quse1.can_represent(quse2))
    nt.ok_(not quse2.can_represent(quse1))

if __name__ == "__main__":
    nose.main()
