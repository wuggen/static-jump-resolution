import nose
import nose.tools as nt

from mock_nodes import *

import angr

from static_jump_resolution.vars import \
        Var, Register, StackVar, MemoryLocation, stack_var, memory_location

import pyvex
import archinfo

amd64 = archinfo.ArchAMD64()
sp = amd64.sp_offset
bp = amd64.bp_offset

def test_stack_var_direct_access():
    addr = pyvex.IRExpr.Get(sp, 'Ity_I64')
    ctx = arbitrary_context()
    ty = 'Ity_I32'

    expected = StackVar(ctx.fn_addr, -24, 4)
    nt.eq_(expected, stack_var(addr, ctx, amd64, ty))

    addr = pyvex.IRExpr.Get(bp, 'Ity_I64')
    ty = 'Ity_I64'

    expected = StackVar(ctx.fn_addr, -8, 8)
    nt.eq_(expected, stack_var(addr, ctx, amd64, ty))

def test_stack_var_offset():
    addr = pyvex.IRExpr.Binop('Iop_Add64', [
        pyvex.IRExpr.Get(sp, 'Ity_I64'),
        pyvex.IRExpr.Const(pyvex.IRConst.U64(8)) ])
    ctx = arbitrary_context()
    ty = 'Ity_I32'

    expected = StackVar(ctx.fn_addr, -16, 4)
    nt.eq_(expected, stack_var(addr, ctx, amd64, ty))

    addr = pyvex.IRExpr.Binop('Iop_Add64', [
        pyvex.IRExpr.Const(pyvex.IRConst.U64(8)),
        pyvex.IRExpr.Get(sp, 'Ity_I64') ])

    nt.eq_(expected, stack_var(addr, ctx, amd64, ty))

    addr = pyvex.IRExpr.Binop('Iop_Sub64', [
        pyvex.IRExpr.Get(bp, 'Ity_I64'),
        pyvex.IRExpr.Const(pyvex.IRConst.U64(8)) ])
    ty = 'Ity_I64'

    expected = StackVar(ctx.fn_addr, -16, 8)
    nt.eq_(expected, stack_var(addr, ctx, amd64, ty))

def test_stack_var_none():
    addr = pyvex.IRExpr.Get(amd64.get_register_by_name("rax").vex_offset, 'Ity_I64')
    ctx = arbitrary_context()
    ty = 'Ity_I32'

    nt.assert_is_none(stack_var(addr, ctx, amd64, ty))

def test_memory_location_actually_stack_var():
    addr = pyvex.IRExpr.Binop('Iop_Sub64', [
        pyvex.IRExpr.Get(bp, 'Ity_I64'),
        pyvex.IRExpr.Const(pyvex.IRConst.U64(16)) ])
    ctx = arbitrary_context()
    ty = 'Ity_I64'

    expected = StackVar(ctx.fn_addr, -24, 8)
    nt.eq_(expected, memory_location(addr, ctx, amd64, ty))

def test_memory_location_general():
    addr = pyvex.IRExpr.Get(amd64.get_register_by_name("rcx").vex_offset, 'Ity_I64')
    ctx = arbitrary_context()
    ty = 'Ity_I64'

    expected = MemoryLocation(addr, 8)
    nt.eq_(expected, memory_location(addr, ctx, amd64, ty))

if __name__ == '__main__':
    nose.main()
