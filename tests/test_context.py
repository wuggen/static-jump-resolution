import nose
import nose.tools as nt

from mock_nodes import *

from static_jump_resolution.context import CtxRecord, CallString

def test_ctx_record_properties():
    [node] = arbitrary_call_nodes(1)
    record = CtxRecord(node, -16, 0)

    nt.eq_(record.stack_ptr, -16)
    nt.eq_(record.base_ptr, 0)
    nt.eq_(record.call_node, node)
    nt.eq_(record.call_addr, node.parent_node.instruction_addrs[-1])

def test_call_string_stack():
    nodes = arbitrary_call_nodes(3)
    callstring = CallString(nodes[:2])

    nt.eq_(callstring.top, nodes[1])
    nt.eq_(callstring.stack, nodes[:2])

    nt.eq_(callstring.pop(), nodes[1])
    nt.eq_(callstring.top, nodes[0])
    nt.eq_(callstring.stack, nodes[:1])

    callstring.push(nodes[2])
    nt.eq_(callstring.top, nodes[2])
    nt.eq_(callstring.stack, [nodes[0], nodes[2]])

def test_call_string_ordering():
    nodes = arbitrary_call_nodes(4)

    cs1 = CallString(nodes)
    cs2 = CallString(nodes)
    nt.ok_(cs1 == cs2)
    nt.ok_(cs1 <= cs2)
    nt.ok_(cs2 <= cs1)
    nt.assert_false(cs1 < cs2)
    nt.assert_false(cs2 < cs1)

    cs1 = CallString(nodes[:3])
    cs2 = CallString(nodes)
    nt.ok_(cs1 != cs2)
    nt.ok_(cs1 < cs2)
    nt.ok_(cs1 <= cs2)

    cs1 = CallString(nodes[:2])
    cs2 = CallString([nodes[0], nodes[2]])
    nt.ok_(cs1 != cs2)
    nt.ok_(cs1 < cs2)
    nt.ok_(cs1 <= cs2)

def test_call_string_represent():
    nodes = arbitrary_call_nodes(4)
    cs1 = CallString(nodes[:3])

    cs2 = CallString(nodes[:1])
    nt.ok_(cs2.can_represent(cs1))

    cs2 = CallString(nodes[:2])
    nt.ok_(cs2.can_represent(cs1))

    cs2 = CallString(nodes[:3])
    nt.ok_(cs2.can_represent(cs1))

    cs2 = CallString(nodes)
    nt.ok_(not cs2.can_represent(cs1))
    nt.ok_(cs1.can_represent(cs2))
