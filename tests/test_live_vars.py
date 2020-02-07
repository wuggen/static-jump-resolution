import nose
import nose.tools as nt

from mock_nodes import *

import angr
from angr.analyses.code_location import CodeLocation

import pyvex
import archinfo

from static_jump_resolution.context import CallString
from static_jump_resolution.live_vars import QualifiedLiveSet, vars_modified, vars_used
from static_jump_resolution.vars import Register, StackVar, MemoryLocation

amd64 = archinfo.ArchAMD64()
sp = amd64.sp_offset
bp = amd64.bp_offset

def test_qualified_live_set_represent():
    nodes = arbitrary_call_nodes(2)
    vars = arbitrary_vars(2)
    uses = arbitrary_var_uses(vars, 1)

    cs1 = CallString(nodes[:1])
    cs2 = CallString(nodes)

    liveset1 = QualifiedLiveSet(cs1, { uses[vars[0]][0] })
    liveset2 = QualifiedLiveSet(cs2, { uses[vars[0]][0] })
    nt.ok_(liveset1.can_represent(liveset2))
    nt.ok_(not liveset2.can_represent(liveset1))

    liveset1.uses |= { uses[vars[1]][0] }
    nt.ok_(not liveset1.can_represent(liveset2))
    nt.ok_(not liveset2.can_represent(liveset1))

def test_qualified_live_set_gen_uses():
    cs = arbitrary_call_string(2)
    vars = arbitrary_vars(4)
    uses1 = arbitrary_var_uses(vars[:2], 1)
    uses2 = arbitrary_var_uses(vars[2:], 1)

    liveset = QualifiedLiveSet(cs, (u for us in uses1.values() for u in us))
    gen_set = [u for us in uses2.values() for u in us]
    expected = QualifiedLiveSet(cs, \
            (u for us in list(uses1.values()) + list(uses2.values()) for u in us))

    liveset.gen_uses(*gen_set)
    nt.eq_(liveset, expected)

def test_qualified_live_set_kill_vars():
    cs = arbitrary_call_string(2)
    vars = arbitrary_vars(2)
    uses = arbitrary_var_uses(vars, 2)

    liveset = QualifiedLiveSet(cs, (u for us in uses.values() for u in us))
    kill = vars[0]
    expected = QualifiedLiveSet(cs, uses[vars[1]])

    liveset.kill_vars(kill)
    nt.eq_(liveset, expected)

def test_vars_modified_store():
    ctx = arbitrary_context()
    rax = amd64.get_register_by_name("rax").vex_offset

    stmt = pyvex.IRStmt.Store(
            pyvex.IRExpr.Get(sp, 'Ity_I64'),
            pyvex.IRExpr.Const(pyvex.IRConst.U32(0)),
            'Iend_LE')
    expected = { StackVar(ctx.fn_addr, DEFAULT_SP, 4) }
    nt.eq_(expected, vars_modified(stmt, ctx, amd64))

    stmt = pyvex.IRStmt.Store(
            pyvex.IRExpr.Binop('Iop_Add64', [
                pyvex.IRExpr.Const(pyvex.IRConst.U64(-8)),
                pyvex.IRExpr.Get(bp, 'Ity_I64') ]),
            pyvex.IRExpr.Get(rax, 'Ity_I16'),
            'Iend_LE')
    expected = { StackVar(ctx.fn_addr, DEFAULT_BP - 8, 2) }
    nt.eq_(expected, vars_modified(stmt, ctx, amd64))

    addr = pyvex.IRExpr.Get(rax, 'Ity_I64')
    stmt = pyvex.IRStmt.Store(
            addr,
            pyvex.IRExpr.Const(pyvex.IRConst.U64(0)),
            'Iend_LE')
    expected = { MemoryLocation(addr, 8) }
    nt.eq_(expected, vars_modified(stmt, ctx, amd64))

def test_vars_modified_put():
    ctx = arbitrary_context()
    rax = amd64.get_register_by_name("rax").vex_offset

    stmt = pyvex.IRStmt.Put(
            pyvex.IRExpr.Const(pyvex.IRConst.U64(0)),
            rax)
    expected = { Register(rax, 8) }
    nt.eq_(expected, vars_modified(stmt, ctx, amd64))

def test_vars_used_put():
    ctx = arbitrary_context()
    rax = amd64.get_register_by_name("rax").vex_offset
    rbx = amd64.get_register_by_name("rbx").vex_offset

    data = pyvex.IRExpr.Const(pyvex.IRConst.U64(0))
    stmt = pyvex.IRStmt.Put(data, rax)

    expected = set()
    nt.eq_(expected, vars_used(stmt, ctx, amd64))

    data = pyvex.IRExpr.Get(rax, 'Ity_I32')
    stmt = pyvex.IRStmt.Put(data, rbx)

    expected = { Register(rax, 4) }
    nt.eq_(expected, vars_used(stmt, ctx, amd64))

    addr = pyvex.IRExpr.Binop('Iop_Add64', [
        pyvex.IRExpr.Get(sp, 'Ity_I64'),
        pyvex.IRExpr.Const(pyvex.IRConst.U64(8)) ])
    data = pyvex.IRExpr.Load('Iend_LE', 'Ity_I32', addr)
    stmt = pyvex.IRStmt.Put(data, rax)

    expected = { StackVar(ctx.fn_addr, DEFAULT_SP + 8, 4) }
    nt.eq_(expected, vars_used(stmt, ctx, amd64))

    addr = pyvex.IRExpr.Get(rax, 'Ity_I64')
    data = pyvex.IRExpr.Load('Iend_LE', 'Ity_I64', addr)
    stmt = pyvex.IRStmt.Put(data, rax)

    expected = { MemoryLocation(addr, 8), Register(rax, 8) }
    nt.eq_(expected, vars_used(stmt, ctx, amd64))

def test_vars_used_store():
    ctx = arbitrary_context()
    rax = amd64.get_register_by_name("rax").vex_offset
    rbx = amd64.get_register_by_name("rbx").vex_offset

    addr = pyvex.IRExpr.Get(rax, 'Ity_I64')
    data = pyvex.IRExpr.Get(rbx, 'Ity_I32')
    stmt = pyvex.IRStmt.Store(addr, data, 'Iend_LE')

    expected = { Register(rax, 8), Register(rbx, 4) }
    nt.eq_(expected, vars_used(stmt, ctx, amd64))

    addr = pyvex.IRExpr.Load('Iend_LE', 'Ity_I64',
            pyvex.IRExpr.Binop('Iop_Add64', [
                pyvex.IRExpr.Get(sp, 'Ity_64'),
                pyvex.IRExpr.Const(pyvex.IRConst.U64(8)) ]))
    data = pyvex.IRExpr.Const(pyvex.IRConst.U32(0))
    stmt = pyvex.IRStmt.Store(addr, data, 'Iend_LE')

    expected = { StackVar(ctx.fn_addr, DEFAULT_SP + 8, 8) }
    nt.eq_(expected, vars_used(stmt, ctx, amd64))

    addr1 = pyvex.IRExpr.Binop('Iop_Add64', [
                pyvex.IRExpr.Get(rax, 'Ity_I64'),
                pyvex.IRExpr.Const(pyvex.IRConst.U64(8)) ])
    addr2 = pyvex.IRExpr.Load('Iend_LE', 'Ity_I64', addr1)
    data = pyvex.IRExpr.Get(rbx, 'Ity_I32')
    stmt = pyvex.IRStmt.Store(addr2, data, 'Iend_LE')

    expected = { MemoryLocation(addr1, 8), Register(rax, 8), Register(rbx, 4) }
    nt.eq_(expected, vars_used(stmt, ctx, amd64))

if __name__ == "__main__":
    nose.main()
