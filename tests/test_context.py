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
    records = arbitrary_records(3)
    callstring = CallString(records[:2])

    nt.eq_(callstring.top, records[1])
    nt.eq_(callstring.stack, records[:2])

    nt.eq_(callstring.pop(), records[1])
    nt.eq_(callstring.top, records[0])
    nt.eq_(callstring.stack, records[:1])

    callstring.push(records[2])
    nt.eq_(callstring.top, records[2])
    nt.eq_(callstring.stack, [records[0], records[2]])

def test_call_string_ordering():
    records = arbitrary_records(4)

    cs1 = CallString(records)
    cs2 = CallString(records)
    nt.ok_(cs1 == cs2)
    nt.ok_(cs1 <= cs2)
    nt.ok_(cs2 <= cs1)
    nt.assert_false(cs1 < cs2)
    nt.assert_false(cs2 < cs1)

    cs1 = CallString(records[:3])
    cs2 = CallString(records)
    nt.ok_(cs1 != cs2)
    nt.ok_(cs1 < cs2)
    nt.ok_(cs1 <= cs2)

    cs1 = CallString(records[:2])
    cs2 = CallString([records[0], records[2]])
    nt.ok_(cs1 != cs2)
    nt.ok_(cs1 < cs2)
    nt.ok_(cs1 <= cs2)

def test_call_string_represent():
    records = arbitrary_records(4)
    cs1 = CallString(records[:3])

    cs2 = CallString(records[:1])
    nt.ok_(cs2.can_represent(cs1))

    cs2 = CallString(records[:2])
    nt.ok_(cs2.can_represent(cs1))

    cs2 = CallString(records[:3])
    nt.ok_(cs2.can_represent(cs1))

    cs2 = CallString(records)
    nt.ok_(not cs2.can_represent(cs1))
    nt.ok_(cs1.can_represent(cs2))
