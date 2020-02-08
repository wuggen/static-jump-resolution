import nose
import nose.tools as nt

import pyvex
import archinfo
import keystone
from keystone import KS_ARCH_X86, KS_MODE_64

from static_jump_resolution.engine import SimEngineSJRVEX, replace_tmps
from static_jump_resolution.live_vars import LiveVars

from vex_util import *

from angr import Block

amd64 = archinfo.ArchAMD64()
ks = keystone.Ks(KS_ARCH_X86, KS_MODE_64)

rsp = amd64.sp_offset
rbp = amd64.bp_offset
rax = amd64.get_register_by_name("rax").vex_offset
rbx = amd64.get_register_by_name("rbx").vex_offset

def test_replace_tmps():
    tmps = {
        0: pyvex.IRExpr.Get(rax, 'Ity_I64'),
        1: pyvex.IRExpr.Get(rbx, 'Ity_I64'),
        2: pyvex.IRExpr.Load('Iend_LE', 'Ity_I32',
            pyvex.IRExpr.RdTmp(0)),
        3: pyvex.IRExpr.Binop('Iop_Add64', [
            pyvex.IRExpr.RdTmp(0),
            pyvex.IRExpr.RdTmp(1) ])
    }

    expr = pyvex.IRExpr.RdTmp(0)
    expected = tmps[0]
    assert_vex_eq(replace_tmps(expr, tmps), expected)

    expr = pyvex.IRExpr.RdTmp(2)
    expected = pyvex.IRExpr.Load('Iend_LE', 'Ity_I32',
            pyvex.IRExpr.Get(rax, 'Ity_I64'))
    assert_vex_eq(replace_tmps(expr, tmps), expected)

    expr = pyvex.IRExpr.RdTmp(3)
    expected = pyvex.IRExpr.Binop('Iop_Add64', [
        pyvex.IRExpr.Get(rax, 'Ity_I64'),
        pyvex.IRExpr.Get(rbx, 'Ity_I64') ])
    assert_vex_eq(replace_tmps(expr, tmps), expected)

def test_engine_process_no_indirect_jumps():
    # If there are no indirect jumps we expect the engine to ignore everything
    bytestr = bytes(ks.asm("xor eax,eax; pop rbp; ret")[0])
    block = Block(0, arch=amd64, byte_string = bytestr)
    engine = SimEngineSJRVEX()

    init_state = LiveVars(amd64, 0)
    expected_final = LiveVars(amd64, 0)

    engine.process(init_state, block=block)
    nt.eq_(engine.state, expected_final)

if __name__ == "__main__":
    nose.main()
