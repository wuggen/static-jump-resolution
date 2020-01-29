import nose
import nose.tools as nt

from mock_nodes import *

import angr
from angr.analyses.code_location import CodeLocation

import pyvex
import archinfo

from static_jump_resolution.context import CallString
from static_jump_resolution.live_vars import QualifiedUse, vars_modified, vars_used
from static_jump_resolution.vars import Register, StackVar, MemoryLocation

amd64 = archinfo.ArchAMD64()
sp = amd64.sp_offset
bp = amd64.bp_offset

def test_qualified_use_represent():
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
