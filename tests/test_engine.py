import nose
import nose.tools as nt

import pyvex
import archinfo

from static_jump_resolution.engine import replace_tmps

from vex_util import *

amd64 = archinfo.ArchAMD64()

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

if __name__ == "__main__":
    nose.main()
