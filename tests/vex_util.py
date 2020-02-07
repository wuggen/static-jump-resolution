import pyvex
import logging

import nose.tools as nt

l = logging.getLogger(__name__)

def const_eq(con1, con2):
    if not isinstance(con1, pyvex.const.IRConst) or not isinstance(con2, pyvex.const.IRConst):
        raise TypeError("[const_eq] Argument is not of type IRConst (arg types %s, %s)" \
                % (type(con1), type(con2)))

    if type(con1) is not type(con2):
        return False

    return con1.value == con2.value

def expr_eq(exp1, exp2):
    if not isinstance(exp1, pyvex.expr.IRExpr) or not isinstance(exp2, pyvex.expr.IRExpr):
        raise TypeError("[expr_eq] Argument is not of type IRExpr (arg types %s, %s)" \
                % (type(exp1), type(exp2)))

    if type(exp1) is not type(exp2):
        return False

    ty = type(exp1)

    if ty is pyvex.IRExpr.RdTmp:
        return exp1.tmp == exp2.tmp

    elif ty is pyvex.IRExpr.Get:
        return exp1.offset == exp2.offset \
                and exp1.ty == exp2.ty

    elif ty in [pyvex.IRExpr.Qop, pyvex.IRExpr.Triop, pyvex.IRExpr.Binop, pyvex.IRExpr.Unop]:
        return exp1.op == exp2.op \
                and all(expr_eq(e1, e2) for (e1, e2) in zip(exp1.args, exp2.args))

    elif ty is pyvex.IRExpr.Load:
        return exp1.end == exp2.end \
                and exp1.ty == exp2.ty \
                and expr_eq(exp1.addr, exp2.addr)

    elif ty is pyvex.IRExpr.Const:
        return const_eq(exp1.con, exp2.con)

    elif ty is pyvex.IRExpr.ITE:
        return expr_eq(exp1.cond, exp2.cond) \
                and expr_eq(exp1.iffalse, exp2.iffalse) \
                and expr_eq(exp1.iftrue, exp2.iftrue)

    else:
        l.warning("[expr_eq] Unimplemented for IRExpr type %s" % ty)
        return False

def stmt_eq(stm1, stm2):
    if not isinstance(stm1, pyvex.stmt.IRStmt) or not isinstance(stm2, pyvex.stmt.IRStmt):
        raise TypeError("[stmt_eq] Argument is not of type IRStmt (arg types %s, %s" \
                % (type(stm1), type(stm2)))

    if type(stm1) is not type(stm2):
        return False

    ty = type(stm1)

    if ty is pyvex.IRStmt.NoOp:
        return True

    elif ty is pyvex.IRStmt.IMark:
        return stm1.addr == stm2.addr \
                and stm1.len == stm2.len \
                and stm1.delta == stm2.delta

    elif ty is pyvex.IRStmt.AbiHint:
        return expr_eq(stm1.base, stm2.base) \
                and stm1.len == stm2.len \
                and expr_eq(stm1.nia, stm2.nia)

    elif ty is pyvex.IRStmt.Put:
        return expr_eq(stm1.data, stm2.data) \
                and stm1.offset == stm2.offset

    elif ty is pyvex.IRStmt.WrTmp:
        return expr_eq(stm1.data, stm2.data) \
                and stm1.tmp == stm2.tmp

    elif ty is pyvex.IRStmt.Store:
        return expr_eq(stm1.addr, stm2.addr) \
                and expr_eq(stm1.data, stm2.data) \
                and stm1.end == stm2.end

    elif ty is pyvex.IRStmt.Exit:
        return expr_eq(stm1.guard, stm2.guard) \
                and expr_eq(stm1.dst, stm2.dst) \
                and stm1.jk == stm2.jk \
                and stm1.offsIP == stm2.offsIP

    else:
        l.warning("[stmt_eq] Unimplemented for IRStmt type %s" % ty)
        return False

def assert_vex_eq(vex1, vex2):
    if isinstance(vex1, pyvex.const.IRConst):
        test = const_eq
    elif isinstance(vex1, pyvex.expr.IRExpr):
        test = expr_eq
    elif isinstance(vex1, pyvex.stmt.IRStmt):
        test = stmt_eq
    else:
        raise TypeError()

    nt.ok_(test(vex1, vex2), "[assert_vex_eq] Objects compare unequal: %s != %s" % (str(vex1), str(vex2)))
