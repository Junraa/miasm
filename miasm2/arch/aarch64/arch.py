#!/usr/bin/env python
#-*- coding:utf-8 -*-

import logging
from pyparsing import *
from miasm2.expression import expression as m2_expr
from miasm2.core.cpu import *
from collections import defaultdict
from miasm2.core.bin_stream import bin_stream
import regs as regs_module
from regs import *
from miasm2.core.asmbloc import asm_label
from miasm2.core.cpu import log as log_cpu
from miasm2.expression.modint import uint32, uint64
import math

log = logging.getLogger("aarch64dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

# refs from A_e_armv8_arm.pdf

# log_cpu.setLevel(logging.DEBUG)


replace_regs = {
    W0: X0[:32],
    W1: X1[:32],
    W2: X2[:32],
    W3: X3[:32],
    W4: X4[:32],
    W5: X5[:32],
    W6: X6[:32],
    W7: X7[:32],
    W8: X8[:32],
    W9: X9[:32],

    W10: X10[:32],
    W11: X11[:32],
    W12: X12[:32],
    W13: X13[:32],
    W14: X14[:32],
    W15: X15[:32],
    W16: X16[:32],
    W17: X17[:32],
    W18: X18[:32],
    W19: X19[:32],

    W20: X20[:32],
    W21: X21[:32],
    W22: X22[:32],
    W23: X23[:32],
    W24: X24[:32],
    W25: X25[:32],
    W26: X26[:32],
    W27: X27[:32],
    W28: X28[:32],
    W29: X29[:32],

    W30: LR[:32],

    WSP: SP[:32],

    WZR: m2_expr.ExprInt32(0),
    XZR: m2_expr.ExprInt64(0),

}


variable, operand, base_expr = gen_base_expr()
_, _, base_expr32 = gen_base_expr()
_, _, base_expr64 = gen_base_expr()


def ast_id2expr32(t):
    if not t in mn_aarch64.regs.all_regs_ids_byname:
        r = m2_expr.ExprId(asm_label(t))
    else:
        r = mn_aarch64.regs.all_regs_ids_byname[t]
    if not r.size == 32:
        raise StopIteration
    return r


def ast_int2expr32(a):
    return m2_expr.ExprInt32(a)


def ast_id2expr64(t):
    if not t in mn_aarch64.regs.all_regs_ids_byname:
        r = m2_expr.ExprId(asm_label(t))
    else:
        r = mn_aarch64.regs.all_regs_ids_byname[t]
    if not r.size == 64:
        raise StopIteration
    return r


def ast_int2expr64(a):
    return m2_expr.ExprInt64(a)

my_var_parser32 = parse_ast(ast_id2expr32, ast_int2expr32)
my_var_parser64 = parse_ast(ast_id2expr64, ast_int2expr64)

base_expr32.setParseAction(my_var_parser32)
base_expr64.setParseAction(my_var_parser64)


int_or_expr = base_expr
int_or_expr32 = base_expr32
int_or_expr64 = base_expr64


shift2expr_dct = {'LSL': '<<', 'LSR': '>>', 'ASR': 'a>>', 'ROR': '>>>'}
shift_str = ["LSL", "LSR", "ASR", "ROR"]
shift_expr = ["<<", ">>", "a>>", '>>>']


def op_shift2expr(s, l, t):
    return shift2expr_dct[t[0]]


def op_shift2expr_slice_at(s, l, t):
    return "slice_at"


def op_ext_reg(s, l, t):
    return t[0]


def shift2expr(t):
    if len(t) == 1:
        return t[0]
    elif len(t) == 3:
        if t[0].size == 32 and isinstance(t[2], m2_expr.ExprInt):
            t[2] = m2_expr.ExprInt32(t[2].arg)
        return m2_expr.ExprOp(t[1], t[0], t[2])
    else:
        raise ValueError('bad string')


def shift2expr_sc(t):
    if len(t) == 1:
        return t[0]
    elif len(t) == 3:
        if t[0].size == 32 and isinstance(t[2], m2_expr.ExprInt):
            t[2] = m2_expr.ExprInt32(t[2].arg)
        if t[1] != '<<':
            raise ValueError('bad op')
        return m2_expr.ExprOp("slice_at", t[0], t[2])
    else:
        raise ValueError('bad string')


def extend2expr(t):
    if len(t) == 1:
        return t[0]
    return m2_expr.ExprOp(t[1], t[0], t[2])


def shiftext2expr(t):
    if len(t) == 1:
        return t[0]
    else:
        return m2_expr.ExprOp(t[1], t[0], t[2])

all_binaryop_lsl_t = literal_list(
    shift_str).setParseAction(op_shift2expr)

all_binaryop_shiftleft_t = literal_list(
    ["LSL"]).setParseAction(op_shift2expr)

extend_lst = ['UXTB', 'UXTH', 'UXTW', 'UXTX', 'SXTB', 'SXTH', 'SXTW', 'SXTX']
extend2_lst = ['UXTW', 'LSL', 'SXTW', 'SXTX']

all_extend_t = literal_list(extend_lst).setParseAction(op_ext_reg)
all_extend2_t = literal_list(extend2_lst).setParseAction(op_ext_reg)


gpregz32_extend = (gpregsz32_info.parser + Optional(
    all_extend_t + int_or_expr32)).setParseAction(extend2expr)
gpregz64_extend = (gpregsz64_info.parser + Optional(
    all_extend_t + int_or_expr64)).setParseAction(extend2expr)


shift32_off = (gpregsz32_info.parser + Optional(all_binaryop_lsl_t +
               (gpregs32_info.parser | int_or_expr))).setParseAction(shift2expr)
shift64_off = (gpregsz64_info.parser + Optional(all_binaryop_lsl_t +
               (gpregs64_info.parser | int_or_expr))).setParseAction(shift2expr)


shiftimm_imm_sc = (int_or_expr + all_binaryop_shiftleft_t +
                   int_or_expr).setParseAction(shift2expr_sc)

shiftimm_off_sc = shiftimm_imm_sc | int_or_expr


shift_off = (shift32_off | shift64_off)
reg_ext_off = (gpregz32_extend | gpregz64_extend)

gpregs_32_64 = (gpregs32_info.parser | gpregs64_info.parser)
gpregsz_32_64 = (gpregsz32_info.parser | gpregsz64_info.parser | int_or_expr)

simdregs = (simd08_info.parser | simd16_info.parser |
            simd32_info.parser | simd64_info.parser)
simdregs_h = (simd32_info.parser | simd64_info.parser | simd128_info.parser)

simdregs_h_zero = (simd32_info.parser |
                   simd64_info.parser | simd128_info.parser | int_or_expr)


def ast_id2expr(t):
    if not t in mn_aarch64.regs.all_regs_ids_byname:
        r = m2_expr.ExprId(asm_label(t))
    else:
        r = mn_aarch64.regs.all_regs_ids_byname[t]
    return r


def ast_int2expr(a):
    return m2_expr.ExprInt64(a)

gpregs_info = {32: gpregs32_info,
               64: gpregs64_info}
gpregsz_info = {32: gpregsz32_info,
                64: gpregsz64_info}


simds_info = {8: simd08_info,
              16: simd16_info,
              32: simd32_info,
              64: simd64_info,
              128: simd128_info}


my_var_parser = parse_ast(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)


def deref2expr_nooff(t):
    t = t[0]
    # XXX default
    return m2_expr.ExprOp("preinc", t[0], m2_expr.ExprInt64(0))


def deref2expr_post(t):
    t = t[0]
    if t[1] in regs_module.all_regs_ids:
        raise StopIteration
    return m2_expr.ExprOp("postinc", t[0], t[1])


def deref2expr_pre(t):
    t = t[0]
    if t[1] in regs_module.all_regs_ids:
        raise StopIteration
    return m2_expr.ExprOp("preinc", t[0], t[1])


def deref2expr_pre_wb(t):
    t = t[0]
    if t[1] in regs_module.all_regs_ids:
        raise StopIteration
    return m2_expr.ExprOp("preinc_wb", t[0], t[1])

LBRACK = Suppress("[")
RBRACK = Suppress("]")
COMMA = Suppress(",")
POSTINC = Suppress("!")

deref_nooff = Group(
    LBRACK + gpregs64_info.parser + RBRACK).setParseAction(deref2expr_nooff)
deref_off_post = Group(LBRACK + gpregs64_info.parser +
                       RBRACK + COMMA + int_or_expr64).setParseAction(deref2expr_post)
deref_off_pre = Group(LBRACK + gpregs64_info.parser +
                      COMMA + int_or_expr64 + RBRACK).setParseAction(deref2expr_pre)
deref_off_pre_wb = Group(LBRACK + gpregs64_info.parser + COMMA +
                         int_or_expr64 + RBRACK + POSTINC).setParseAction(deref2expr_pre_wb)

deref = (deref_off_post | deref_off_pre_wb | deref_off_pre | deref_nooff)


def deref_ext2op(t):
    t = t[0]
    if len(t) == 4:
        expr = set_imm_to_size(t[1].size, t[3])
        if expr is None:
            raise StopIteration
        return m2_expr.ExprOp('segm', t[0], m2_expr.ExprOp(t[2], t[1], expr))
    elif len(t) == 2:
        return m2_expr.ExprOp('segm', t[0], t[1])

    raise ValueError("cad deref")

deref_ext2 = Group(LBRACK + gpregs_32_64 + COMMA + gpregs_32_64 +
                   Optional(all_extend2_t + int_or_expr) + RBRACK).setParseAction(deref_ext2op)


class additional_info:

    def __init__(self):
        self.except_on_instr = False
        self.lnk = None
        self.cond = None

CONDS = [
    'EQ', 'NE', 'CS', 'CC',
    'MI', 'PL', 'VS', 'VC',
    'HI', 'LS', 'GE', 'LT',
    'GT', 'LE', 'AL', 'NV']

CONDS_INV = [
    'NE', 'EQ', 'CC', 'CS',
    'PL', 'MI', 'VC', 'VS',
    'LS', 'HI', 'LT', 'GE',
    'LE', 'GT', 'NV', 'AL']

BRCOND = ['B.' + cond for cond in CONDS] + ['CBZ', 'CBNZ', 'TBZ', 'TBNZ']

# for conditional selec
conds_expr, _, conds_info = gen_regs(CONDS, {})
conds_inv_expr, _, conds_inv_info = gen_regs(CONDS_INV, {})


class instruction_aarch64(instruction):
    delayslot = 0

    def __init__(self, *args, **kargs):
        super(instruction_aarch64, self).__init__(*args, **kargs)

    @staticmethod
    def arg2str(e, pos=None):
        wb = False
        if isinstance(e, m2_expr.ExprId) or isinstance(e, m2_expr.ExprInt):
            return str(e)
        elif isinstance(e, m2_expr.ExprOp) and e.op in shift_expr:
            op_str = shift_str[shift_expr.index(e.op)]
            return "%s %s %s" % (e.args[0], op_str, e.args[1])
        elif isinstance(e, m2_expr.ExprOp) and e.op == "slice_at":
            return "%s LSL %s" % (e.args[0], e.args[1])
        elif isinstance(e, m2_expr.ExprOp) and e.op in extend_lst:
            op_str = e.op
            return "%s %s %s" % (e.args[0], op_str, e.args[1])
        elif isinstance(e, m2_expr.ExprOp) and e.op == "postinc":
            if e.args[1].arg != 0:
                return "[%s], %s" % (e.args[0], e.args[1])
            else:
                return "[%s]" % (e.args[0])
        elif isinstance(e, m2_expr.ExprOp) and e.op == "preinc_wb":
            if e.args[1].arg != 0:
                return "[%s, %s]!" % (e.args[0], e.args[1])
            else:
                return "[%s]" % (e.args[0])
        elif isinstance(e, m2_expr.ExprOp) and e.op == "preinc":
            if len(e.args) == 1:
                return "[%s]" % (e.args[0])
            elif not isinstance(e.args[1], m2_expr.ExprInt) or e.args[1].arg != 0:
                return "[%s, %s]" % (e.args[0], e.args[1])
            else:
                return "[%s]" % (e.args[0])
        elif isinstance(e, m2_expr.ExprOp) and e.op == 'segm':
            arg = e.args[1]
            if isinstance(arg, m2_expr.ExprId):
                arg = str(arg)
            elif arg.op == 'LSL' and arg.args[1].arg == 0:
                arg = str(arg.args[0])
            else:
                arg = "%s %s %s" % (arg.args[0], arg.op, arg.args[1])
            return '[%s, %s]' % (e.args[0], arg)

        else:
            raise NotImplementedError("bad op")

    def dstflow(self):
        return self.name in self.name in BRCOND + ["B", "BL"]

    def mnemo_flow_to_dst_index(self, name):
        if self.name in ['CBZ', 'CBNZ']:
            return 1
        elif self.name in ['TBZ', 'TBNZ']:
            return 2
        else:
            return 0

    def dstflow2label(self, symbol_pool):
        index = self.mnemo_flow_to_dst_index(self.name)
        e = self.args[index]
        if not isinstance(e, m2_expr.ExprInt):
            return
        ad = e.arg + self.offset
        l = symbol_pool.getby_offset_create(ad)
        s = m2_expr.ExprId(l, e.size)
        self.args[index] = s

    def breakflow(self):
        return self.name in BRCOND + ["BR", "BLR", "RET", "ERET", "DRPS", "B", "BL"]

    def is_subcall(self):
        return self.name in ["BLR", "BL"]

    def getdstflow(self, symbol_pool):
        index = self.mnemo_flow_to_dst_index(self.name)
        return [self.args[index]]

    def splitflow(self):
        return self.name in BRCOND + ["BLR", "BL"]

    def get_symbol_size(self, symbol, symbol_pool):
        return 64

    def fixDstOffset(self):
        index = self.mnemo_flow_to_dst_index(self.name)
        e = self.args[index]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, m2_expr.ExprInt):
            log.debug('dyn dst %r', e)
            return
        off = e.arg - self.offset
        if int(off % 4):
            raise ValueError('strange offset! %r' % off)
        self.args[index] = m2_expr.ExprInt64(off)



class mn_aarch64(cls_mn):
    delayslot = 0
    name = "aarch64"
    regs = regs_module
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = {'l': PC, 'b': PC}
    sp = {'l': SP, 'b': SP}
    instruction = instruction_aarch64
    max_instruction_len = 4
    alignment = 4

    @classmethod
    def getpc(cls, attrib=None):
        return PC

    @classmethod
    def getsp(cls, attrib=None):
        return SP

    def additional_info(self):
        info = additional_info()
        info.lnk = False
        if hasattr(self, "lnk"):
            info.lnk = self.lnk.value != 0
        return info

    @classmethod
    def getbits(cls, bs, attrib, start, n):
        if not n:
            return 0
        o = 0
        if n > bs.getlen() * 8:
            raise ValueError('not enought bits %r %r' % (n, len(bs.bin) * 8))
        while n:
            offset = start / 8
            n_offset = cls.endian_offset(attrib, offset)
            c = cls.getbytes(bs, n_offset, 1)
            if not c:
                raise IOError
            c = ord(c)
            r = 8 - start % 8
            c &= (1 << r) - 1
            l = min(r, n)
            c >>= (r - l)
            o <<= l
            o |= c
            n -= l
            start += l
        return o

    @classmethod
    def endian_offset(cls, attrib, offset):
        if attrib == "l":
            return (offset & ~3) + 3 - offset % 4
        elif attrib == "b":
            return offset
        else:
            raise NotImplementedError('bad attrib')

    @classmethod
    def check_mnemo(cls, fields):
        l = sum([x.l for x in fields])
        assert l == 32, "len %r" % l

    @classmethod
    def getmn(cls, name):
        return name.upper()

    @classmethod
    def mod_fields(cls, fields):
        l = sum([x.l for x in fields])
        if l == 32:
            return fields
        return fields

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def value(self, mode):
        v = super(mn_aarch64, self).value(mode)
        if mode == 'l':
            return [x[::-1] for x in v]
        elif mode == 'b':
            return [x for x in v]
        else:
            raise NotImplementedError('bad attrib')

    def get_symbol_size(self, symbol, symbol_pool, mode):
        return 32

    def reset_class(self):
        super(mn_aarch64, self).reset_class()
        if hasattr(self, "sf"):
            self.sf.value = None


def aarch64op(name, fields, args=None, alias=False):
    dct = {"fields": fields, "alias":alias}
    if args is not None:
        dct['args'] = args
    type(name, (mn_aarch64,), dct)


class aarch64_gpreg_noarg(reg_noarg):
    parser = gpregs_32_64
    gpregs_info = gpregs_info

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        self.expr = self.gpregs_info[size].expr[v]
        return True

    def encode(self):
        if not test_set_sf(self.parent, self.expr.size):
            return False
        if not self.expr.size in self.gpregs_info:
            return False
        if not self.expr in self.gpregs_info[self.expr.size].expr:
            return False
        self.value = self.gpregs_info[self.expr.size].expr.index(self.expr)
        return True


class aarch64_simdreg(reg_noarg, m_arg):
    parser = simdregs
    simd_size = [8, 16, 32, 64]

    def decode(self, v):
        if self.parent.size.value > len(self.simd_size):
            return False
        size = self.simd_size[self.parent.size.value]
        self.expr = simds_info[size].expr[v]
        return True

    def encode(self):
        if not self.expr.size in self.simd_size:
            return False
        if not self.expr in simds_info[self.expr.size].expr:
            return False
        self.value = simds_info[self.expr.size].expr.index(self.expr)
        self.parent.size.value = self.simd_size.index(self.expr.size)
        return True


class aarch64_simdreg_h(aarch64_simdreg):
    parser = simdregs_h
    simd_size = [32, 64, 128]


class aarch64_simdreg_32_64(aarch64_simdreg):
    parser = simdregs_h
    simd_size = [32, 64]


class aarch64_simdreg_32_64_zero(aarch64_simdreg_32_64):
    parser = simdregs_h_zero

    def decode(self, v):
        if v == 0 and self.parent.opc.value == 1:
            size = 64 if self.parent.size.value else 32
            self.expr = m2_expr.ExprInt_fromsize(size, 0)
            return True
        else:
            return super(aarch64_simdreg_32_64_zero, self).decode(v)

    def encode(self):
        if isinstance(self.expr, m2_expr.ExprInt):
            self.parent.opc.value = 1
            self.value = 0
            return True
        else:
            self.parent.opc.value = 0
            return super(aarch64_simdreg_32_64_zero, self).encode()


class aarch64_gpreg_isf(reg_noarg, m_arg):
    parser = gpregs_32_64

    def decode(self, v):
        size = 32 if self.parent.sf.value else 64
        self.expr = gpregs_info[size].expr[v]
        return True

    def encode(self):
        if not self.expr in gpregs_info[self.expr.size].expr:
            return False
        self.value = gpregs_info[self.expr.size].expr.index(self.expr)
        self.parent.sf.value = 1 if self.expr.size == 32 else 0
        return True


class aarch64_gpreg(aarch64_gpreg_noarg, m_arg):
    pass


class aarch64_gpreg_n1(aarch64_gpreg):

    def decode(self, v):
        if v == 0b11111:
            return False
        return super(aarch64_gpreg_n1, self).decode(v)

    def encode(self):
        super(aarch64_gpreg_n1, self).encode()
        return self.value != 0b11111


class aarch64_gpregz(aarch64_gpreg_noarg, m_arg):
    parser = gpregsz_32_64
    gpregs_info = gpregsz_info


class aarch64_gpreg0(bsi, m_arg):
    parser = gpregsz_32_64
    gpregs_info = gpregsz_info

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        if v == 0x1F:
            self.expr = m2_expr.ExprInt_fromsize(size, 0)
        else:
            self.expr = self.gpregs_info[size].expr[v]
        return True

    def encode(self):
        if isinstance(self.expr, m2_expr.ExprInt):
            if self.expr.arg == 0:
                self.value = 0x1F
                return True
            return False
        if not self.expr.size in self.gpregs_info:
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        if not self.expr in self.gpregs_info[self.expr.size].expr:
            return False
        self.value = self.gpregs_info[self.expr.size].expr.index(self.expr)
        return True


class aarch64_crreg(reg_noarg, m_arg):
    reg_info = cr_info
    parser = reg_info.parser


class aarch64_gpreg32_nodec(bsi):
    reg_info = gpregs32_info


class aarch64_gpreg64_nodec(bsi):
    reg_info = gpregs64_info


class aarch64_gpreg32_noarg(reg_noarg):
    reg_info = gpregs32_info
    parser = reg_info.parser


class aarch64_gpreg32(aarch64_gpreg32_noarg, m_arg):
    reg_info = gpregs32_info
    parser = reg_info.parser


class aarch64_gpreg64_noarg(reg_noarg):
    reg_info = gpregs64_info
    parser = reg_info.parser


class aarch64_gpreg64(reg_noarg, m_arg):
    reg_info = gpregs64_info
    parser = reg_info.parser


class aarch64_gpregz32_noarg(reg_noarg):
    reg_info = gpregsz32_info
    parser = reg_info.parser


class aarch64_gpregz32(aarch64_gpreg32_noarg, m_arg):
    reg_info = gpregsz32_info
    parser = reg_info.parser


class aarch64_gpregz64_noarg(reg_noarg):
    reg_info = gpregsz64_info
    parser = reg_info.parser


class aarch64_gpregz64(reg_noarg, m_arg):
    reg_info = gpregsz64_info
    parser = reg_info.parser


class aarch64_simd08_noarg(reg_noarg):
    reg_info = simd08_info
    parser = reg_info.parser


class aarch64_simd08(aarch64_simd08_noarg, m_arg):
    reg_info = simd08_info
    parser = reg_info.parser


class aarch64_simd16_noarg(reg_noarg):
    reg_info = simd16_info
    parser = reg_info.parser


class aarch64_simd16(aarch64_simd16_noarg, m_arg):
    reg_info = simd16_info
    parser = reg_info.parser


class aarch64_simd32_noarg(reg_noarg):
    reg_info = simd32_info
    parser = reg_info.parser


class aarch64_simd32(aarch64_simd32_noarg, m_arg):
    reg_info = simd32_info
    parser = reg_info.parser


class aarch64_simd64_noarg(reg_noarg):
    reg_info = simd64_info
    parser = reg_info.parser


class aarch64_simd64(aarch64_simd64_noarg, m_arg):
    reg_info = simd64_info
    parser = reg_info.parser


class aarch64_simd128_noarg(reg_noarg):
    reg_info = simd128_info
    parser = reg_info.parser


class aarch64_simd128(aarch64_simd128_noarg, m_arg):
    reg_info = simd128_info
    parser = reg_info.parser


class aarch64_imm_32(imm_noarg, m_arg):
    parser = base_expr


class aarch64_imm_64(aarch64_imm_32):
    parser = base_expr


class aarch64_int64_noarg(int32_noarg):
    parser = base_expr
    intsize = 64
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: m2_expr.ExprInt64(
        sign_ext(x, self.l, self.intsize))


class aarch64_uint64_noarg(imm_noarg):
    parser = base_expr
    intsize = 64
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: m2_expr.ExprInt64(x)


class aarch64_uint64(aarch64_uint64_noarg, m_arg):
    parser = base_expr


def set_imm_to_size(size, expr):
    if size == expr.size:
        return expr
    if size > expr.size:
        expr = m2_expr.ExprInt_fromsize(size, expr.arg)
    else:
        if expr.arg > (1 << size) - 1:
            return None
        expr = m2_expr.ExprInt_fromsize(size, expr.arg)
    return expr


class aarch64_imm_sf(imm_noarg):
    parser = base_expr

    def fromstring(self, s, parser_result=None):
        start, stop = super(aarch64_imm_sf, self).fromstring(s, parser_result)
        if start is None:
            return start, stop
        size = self.parent.args[0].expr.size
        if self.expr in gpregs64_info.expr + gpregs32_info.expr:
            return None, None
        if isinstance(self.expr, m2_expr.ExprOp):
            return False
        expr = set_imm_to_size(size, self.expr)
        if expr is None:
            return None, None
        self.expr = expr
        return start, stop

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        value = int(self.expr.arg)
        if value >= 1 << self.l:
            return False
        self.value = value
        return True

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        self.expr = m2_expr.ExprInt_fromsize(size, v)
        return True


class aarch64_imm_sft(aarch64_imm_sf, m_arg):

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        value = int(self.expr.arg)
        if value < 1 << self.l:
            self.parent.shift.value = 0
        else:
            if value & 0xFFF:
                return False
            value >>= 12
            if value >= 1 << self.l:
                return False
            self.parent.shift.value = 1
        self.value = value
        return True

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        if self.parent.shift.value == 0:
            self.expr = m2_expr.ExprInt_fromsize(size, v)
        elif self.parent.shift.value == 1:
            self.expr = m2_expr.ExprInt_fromsize(size, v << 12)
        else:
            return False
        return True

OPTION2SIZE = [32, 32, 32, 64,
               32, 32, 32, 64]


class aarch64_gpreg_ext(reg_noarg, m_arg):
    parser = reg_ext_off

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprOp):
            return False
        if self.expr.op not in extend_lst:
            return False
        reg, amount = self.expr.args

        if not reg in gpregsz_info[self.expr.size].expr:
            return False
        self.value = gpregsz_info[self.expr.size].expr.index(reg)
        option = extend_lst.index(self.expr.op)
        if self.expr.size != OPTION2SIZE[option]:
            if not test_set_sf(self.parent, self.expr.size):
                return False
        self.parent.option.value = option
        self.parent.imm.value = int(amount.arg)
        return True

    def decode(self, v):
        if self.parent.sf.value == 0:
            size = 64 if self.parent.sf.value else 32
        else:
            size = OPTION2SIZE[self.parent.option.value]
        reg = gpregsz_info[size].expr[v]

        self.expr = m2_expr.ExprOp(extend_lst[self.parent.option.value],
                           reg, m2_expr.ExprInt_from(reg, self.parent.imm.value))
        return True

EXT2_OP = {0b010: 'UXTW',
           0b011: 'LSL',
           0b110: 'SXTW',
           0b111: 'SXTX'}
EXT2_OP_INV = dict([(items[1], items[0]) for items in EXT2_OP.items()])


class aarch64_gpreg_ext2(reg_noarg, m_arg):
    parser = deref_ext2

    def get_size(self):
        return self.parent.size.value

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprOp):
            return False
        arg0, arg1 = self.expr.args
        if not (isinstance(self.expr, m2_expr.ExprOp) and self.expr.op == 'segm'):
            return False
        if not arg0 in self.parent.rn.reg_info.expr:
            return False
        self.parent.rn.value = self.parent.rn.reg_info.expr.index(arg0)
        is_reg = False
        self.parent.shift.value = 0
        if isinstance(arg1, m2_expr.ExprId):
            reg = arg1
            self.parent.option.value = 0b011
            is_reg = True
        elif isinstance(arg1, m2_expr.ExprOp) and arg1.op in EXT2_OP.values():
            reg = arg1.args[0]
        else:
            return False
        if not (reg.size in gpregs_info and
                reg in gpregs_info[reg.size].expr):
            return False
        self.value = gpregs_info[reg.size].expr.index(reg)
        if is_reg:
            return True
        if not (isinstance(arg1.args[1], m2_expr.ExprInt)):
            return False
        if arg1.op not in EXT2_OP_INV:
            return False
        self.parent.option.value = EXT2_OP_INV[arg1.op]
        if arg1.args[1].arg == 0:
            self.parent.shift.value = 0
            return True

        if arg1.args[1].arg != self.get_size():
            return False

        self.parent.shift.value = 1

        return True

    def decode(self, v):
        opt = self.parent.option.value
        if opt in [0, 1, 4, 5]:
            return False
        elif opt in [2, 6]:
            reg_expr = gpregsz32_info.expr
        elif opt in [3, 7]:
            reg_expr = gpregsz64_info.expr
        arg = reg_expr[v]

        if opt in EXT2_OP:
            if self.parent.shift.value == 1:
                arg = m2_expr.ExprOp(EXT2_OP[opt], arg,
                             m2_expr.ExprInt_from(arg, self.get_size()))
            else:
                arg = m2_expr.ExprOp(EXT2_OP[opt], arg,
                             m2_expr.ExprInt_from(arg, 0))

        reg = self.parent.rn.reg_info.expr[self.parent.rn.value]
        self.expr = m2_expr.ExprOp('segm', reg, arg)
        return True


class aarch64_gpreg_ext2_128(aarch64_gpreg_ext2):

    def get_size(self):
        return 4


def test_set_sf(parent, size):
    if not hasattr(parent, 'sf'):
        return False
    if parent.sf.value == None:
        parent.sf.value = 1 if size == 64 else 0
        return True
    psize = 64 if parent.sf.value else 32
    return psize == size


class aarch64_gpreg_sftimm(reg_noarg, m_arg):
    reg_info = gpregsz_info
    parser = shift_off

    def encode(self):
        size = self.expr.size
        if not test_set_sf(self.parent, size):
            return False
        if isinstance(self.expr, m2_expr.ExprId):
            if not size in gpregs_info:
                return False
            if not self.expr in self.reg_info[size].expr:
                return False
            self.parent.shift.value = 0
            self.parent.imm.value = 0
            self.value = self.reg_info[size].expr.index(self.expr)
            return True

        if not isinstance(self.expr, m2_expr.ExprOp):
            return False
        if not self.expr.op in shift_expr:
            return False
        args = self.expr.args
        if not args[0] in self.reg_info[size].expr:
            return False
        if not isinstance(args[1], m2_expr.ExprInt):
            return False
        self.parent.shift.value = shift_expr.index(self.expr.op)
        self.parent.imm.value = int(args[1].arg)
        self.value = self.reg_info[size].expr.index(args[0])
        return True

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        e = self.reg_info[size].expr[v]
        amount = self.parent.imm.value
        if amount != 0:
            e = m2_expr.ExprOp(
                shift_expr[self.parent.shift.value], e, m2_expr.ExprInt_from(e, amount))
        self.expr = e
        return True


def ror(value, amount, size):
    return (value >> amount) | (value << (size - amount))


def rol(value, amount, size):
    return (value << amount) | (value >> (size - amount))

UINTS = {32: uint32, 64: uint64}


def imm_to_imm_rot_form(value, size):
    for i in xrange(0, size):
        mod_value = int(rol(value, i, size))
        if (mod_value + 1) & mod_value == 0:
            return i
    return None


class aarch64_imm_nsr(aarch64_imm_sf, m_arg):
    parser = base_expr

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        mask = UINTS[size]((1 << (v + 1)) - 1)
        mask = ror(mask, self.parent.immr.value, size)
        self.expr = m2_expr.ExprInt_fromsize(size, mask)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        value = self.expr.arg
        if value == 0:
            return False

        index = imm_to_imm_rot_form(value, self.expr.size)
        if index == None:
            return False
        power = int(rol(value, index, self.expr.size)) + 1
        length = None
        for i in xrange(self.expr.size):
            if 1 << i == power:
                length = i
                break
        if length is None:
            return False
        self.parent.immr.value = index
        self.value = length - 1
        self.parent.immn.value = 1 if self.expr.size == 64 else 0
        return True


class aarch64_pcoff(aarch64_imm_32):
    parser = base_expr


class aarch64_immhip_page(aarch64_imm_32):
    parser = base_expr

    def decode(self, v):
        v = ((v << 2) | self.parent.immlo.value) << 12
        v = sign_ext(v, 33, 64)
        self.expr = m2_expr.ExprInt64(v)
        return True

    def encode(self):
        v = int(self.expr.arg)
        if v & (1 << 63):
            v &= (1 << 33) - 1
        if v & 0xfff:
            return False
        v >>= 12
        self.parent.immlo.value = v & 3
        v >>= 2
        self.value = v
        return True


class aarch64_immhi_page(aarch64_imm_32):
    parser = base_expr

    def decode(self, v):
        v = ((v << 2) | self.parent.immlo.value)
        v = sign_ext(v, 21, 64)
        self.expr = m2_expr.ExprInt64(v)
        return True

    def encode(self):
        v = int(self.expr.arg)
        if v & (1 << 63):
            v &= (1 << 33) - 1
        self.parent.immlo.value = v & 3
        v >>= 2
        if v > (1 << 19) - 1:
            return False
        self.value = v & ((1 << 19) - 1)
        return True


class aarch64_imm_hw(m_arg):
    parser = base_expr
    shift_op = '<<'

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        self.expr = m2_expr.ExprInt_fromsize(size, v << (16 * self.parent.hw.value))
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        size = self.parent.args[0].expr.size
        if set_imm_to_size(size, self.expr) is None:
            return False
        value = int(self.expr.arg)
        mask = (1 << size) - 1
        for i in xrange(size / 16):
            if ((0xffff << (i * 16)) ^ mask) & value:
                continue
            self.parent.hw.value = i
            self.value = value >> (i * 16)
            return True
        return False


class aarch64_imm_hw_sc(m_arg):
    parser = shiftimm_off_sc
    shift_op = 'slice_at'

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        expr = m2_expr.ExprInt_fromsize(size, v)
        amount = m2_expr.ExprInt_fromsize(size, 16 * self.parent.hw.value)
        if self.parent.hw.value:
            self.expr = m2_expr.ExprOp(self.shift_op, expr,  amount)
        else:
            self.expr = expr
        return True

    def encode(self):
        if isinstance(self.expr, m2_expr.ExprInt):
            if self.expr.arg > 0xFFFF:
                return False
            self.value = int(self.expr.arg)
            self.parent.hw.value = 0
            return True

        if not (isinstance(self.expr, m2_expr.ExprOp) and
                self.expr.op == self.shift_op and
                len(self.expr.args) == 2 and
                isinstance(self.expr.args[0], m2_expr.ExprInt) and
                isinstance(self.expr.args[1], m2_expr.ExprInt)):
            return False
        if set_imm_to_size(self.parent.args[0].expr.size, self.expr.args[0]) is None:
            return False
        if set_imm_to_size(self.parent.args[0].expr.size, self.expr.args[1]) is None:
            return False
        arg, amount = [int(arg.arg) for arg in self.expr.args]
        if arg > 0xFFFF:
            return False
        if amount % 16 or amount / 16 > 4:
            return False
        self.value = arg
        self.parent.hw.value = amount / 16
        return True


class aarch64_offs(imm_noarg, m_arg):
    parser = base_expr

    def decode(self, v):
        v = v & self.lmask
        v = (v << 2)
        v = sign_ext(v, (self.l + 2), 64)
        self.expr = m2_expr.ExprInt64(v)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        v = int(self.expr.arg)
        if v & (1 << 63):
            v &= (1 << (self.l + 2)) - 1
        self.value = v >> 2
        return True


def set_mem_off(parent, imm):
    if hasattr(parent, 'simm'):
        mask = (1 << parent.simm.l) - 1
        if imm != sign_ext(imm & mask, parent.simm.l, 64):
            return False
        parent.simm.value = imm & mask
    elif hasattr(parent, 'uimm'):
        mask = (1 << parent.uimm.l) - 1
        if imm > mask:
            return False
        parent.uimm.value = imm
    else:
        raise ValueError('unknown imm')
    return True


def get_size(parent):
    if not hasattr(parent, "size"):
        return 0
    if hasattr(parent.size, "amount"):
        size = parent.size.amount
    else:
        size = parent.size.value
    return size


class aarch64_deref(m_arg):
    parser = deref

    def decode_w_size(self, off):
        return off

    def encode_w_size(self, off):
        return off

    def get_postpre(self, parent):
        if hasattr(self.parent, "postpre"):
            if self.parent.postpre.value == 0:
                op = 'postinc'
            else:
                op = 'preinc_wb'
        else:
            op = 'preinc'
        return op

    def decode(self, v):
        reg = gpregs64_info.expr[v]
        off = self.parent.imm.expr.arg
        op = self.get_postpre(self.parent)
        off = self.decode_w_size(off)
        self.expr = m2_expr.ExprOp(op, reg, m2_expr.ExprInt64(off))
        return True

    def encode(self):
        expr = self.expr
        if not isinstance(expr, m2_expr.ExprOp):
            return False
        if not expr.op in ['postinc', 'preinc_wb', 'preinc']:
            return False
        if hasattr(self.parent, "postpre"):
            if expr.op == 'postinc':
                self.parent.postpre.value = 0
            else:
                self.parent.postpre.value = 1
        reg, off = expr.args
        if not reg in gpregs64_info.expr:
            return False
        if not isinstance(off, m2_expr.ExprInt):
            return False
        imm = int(off.arg)
        imm = self.encode_w_size(imm)
        if imm is False:
            return False
        self.parent.imm.expr = m2_expr.ExprInt64(imm)
        if not self.parent.imm.encode():
            return False
        self.value = gpregs64_info.expr.index(reg)
        return True


class aarch64_deref_size(aarch64_deref):

    def decode_w_size(self, off):
        size = get_size(self.parent)
        return off << size

    def encode_w_size(self, off):
        size = get_size(self.parent)
        if size:
            if off & ((1 << size) - 1):
                return False
            off >>= size
        return off


class aarch64_deref_nooff(aarch64_deref):
    parser = deref_nooff

    def decode(self, v):
        reg = gpregs64_info.expr[v]
        self.expr = m2_expr.ExprOp('preinc', reg)
        return True

    def encode(self):
        expr = self.expr
        if not isinstance(expr, m2_expr.ExprOp):
            return False
        if expr.op != 'preinc':
            return False
        if len(expr.args) == 1:
            reg = expr.args[0]
        elif len(expr.args) == 2:
            reg, off = expr.args
            if not isinstance(off, m2_expr.ExprInt):
                return False
            if off.arg != 0:
                return False
        else:
            return False

        if not reg in gpregs64_info.expr:
            return False
        self.value = gpregs64_info.expr.index(reg)
        return True


class aarch64_sf_scale(aarch64_deref):
    size2scale = {32: 2, 64: 3}

    def decode_w_size(self, off):
        size = 2 + self.parent.sf.value
        return off << size

    def encode_w_size(self, off):
        size = self.parent.args[0].expr.size
        if not size in self.size2scale:
            return False
        scale = self.size2scale[size]
        off = int(mod_size2int[size](off) >> scale)
        return off


class aarch64_sd_scale(aarch64_sf_scale):
    size2scale = {32: 2, 64: 3, 128: 4}

    def decode_w_size(self, off):
        size = 2 + self.parent.size.value
        return off << size


class aarch64_eq(bsi):

    def decode(self, v):
        return getattr(self.parent, self.ref).value == v

    def encode(self):
        self.value = getattr(self.parent, self.ref).value
        return True
modf = bs_mod_name(l=1, fname='modf', mn_mod=['', 'S'])
sf = bs(l=1, fname='sf', order=-1)


class aarch64_cond_arg(reg_noarg, m_arg):
    reg_info = conds_info
    parser = reg_info.parser


class aarch64_cond_inv_arg(reg_noarg, m_arg):
    reg_info = conds_inv_info
    parser = reg_info.parser


class aarch64_b40(m_arg):
    parser = base_expr

    def decode(self, v):
        self.expr = m2_expr.ExprInt_from(
            self.parent.rt.expr, (self.parent.sf.value << self.l) | v)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        size = self.parent.args[0].expr.size
        value = int(self.expr.arg)
        self.value = value & self.lmask
        if self.parent.sf.value is None:
            self.parent.sf.value = value >> self.l
            return True
        else:
            return value >> self.l == self.parent.sf.value


shift = bs(l=2, fname='shift')

shiftb = bs(l=1, fname='shift', order=-1)


rn64_v = bs(l=5, cls=(aarch64_gpreg64_nodec,), fname='rn', order=-1)

rn = bs(l=5, cls=(aarch64_gpreg,), fname="rn")
rs = bs(l=5, cls=(aarch64_gpreg,), fname="rs")
rm = bs(l=5, cls=(aarch64_gpreg,), fname="rm")
rd = bs(l=5, cls=(aarch64_gpreg,), fname="rd")
ra = bs(l=5, cls=(aarch64_gpregz,), fname="ra")
rt = bs(l=5, cls=(aarch64_gpregz,), fname="rt")
rt2 = bs(l=5, cls=(aarch64_gpregz,), fname="rt2")
rn0 = bs(l=5, cls=(aarch64_gpreg0,), fname="rn")

rmz = bs(l=5, cls=(aarch64_gpregz,), fname="rm")
rnz = bs(l=5, cls=(aarch64_gpregz,), fname="rn")


rn_n1 = bs(l=5, cls=(aarch64_gpreg_n1,), fname="rn")
rm_n1 = bs(l=5, cls=(aarch64_gpreg_n1,), fname="rm")


rn_na = bs(l=5, cls=(aarch64_gpreg_noarg,), fname="rn", order=-1)
rn32_na = bs(l=5, cls=(aarch64_gpreg32_noarg,), fname="rn", order=-1)
rn64_na = bs(l=5, cls=(aarch64_gpreg64_noarg,), fname="rn", order=-1)

sd1 = bs(l=5, cls=(aarch64_simdreg_h,), fname="rt")
sd2 = bs(l=5, cls=(aarch64_simdreg_h,), fname="rt2")

sdn_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="rn")
sdd_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="rd")
sdm_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="rm")
sda_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="ra")


sdm_32_64_zero = bs(l=5, cls=(aarch64_simdreg_32_64_zero,), fname="rm")

crn = bs(l=4, cls=(aarch64_crreg,), fname="crn")
crm = bs(l=4, cls=(aarch64_crreg,), fname="crm")


rn64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rn")
rs64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rs")
rm64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rm")
rd64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rd")
rt64 = bs(l=5, cls=(aarch64_gpregz64,), fname="rt")
ra64 = bs(l=5, cls=(aarch64_gpregz64,), fname="ra")

rn32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rn")
rm32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rm")
rd32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rd")
rs32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rs")

sd08 = bs(l=5, cls=(aarch64_simd08,), fname="rd")
sd16 = bs(l=5, cls=(aarch64_simd16,), fname="rd")
sd32 = bs(l=5, cls=(aarch64_simd32,), fname="rd")
sd64 = bs(l=5, cls=(aarch64_simd64,), fname="rd")
sd128 = bs(l=5, cls=(aarch64_simd128,), fname="rd")

sn08 = bs(l=5, cls=(aarch64_simd08,), fname="rn")
sn16 = bs(l=5, cls=(aarch64_simd16,), fname="rn")
sn32 = bs(l=5, cls=(aarch64_simd32,), fname="rn")
sn64 = bs(l=5, cls=(aarch64_simd64,), fname="rn")
sn128 = bs(l=5, cls=(aarch64_simd128,), fname="rn")


rt32 = bs(l=5, cls=(aarch64_gpregz32,), fname="rt")

rt_isf = bs(l=5, cls=(aarch64_gpreg_isf,), fname="rt")

rn64_deref = bs(l=5, cls=(aarch64_deref,), fname="rn")
rn64_deref_sz = bs(l=5, cls=(aarch64_deref_size,), fname="rn")
rn64_deref_sf = bs(l=5, cls=(aarch64_sf_scale,), fname="rn")
rn64_deref_sd = bs(l=5, cls=(aarch64_sd_scale,), fname="rn")

rn64_deref_nooff = bs(l=5, cls=(aarch64_deref_nooff,), fname="rn")

imm_sft_12 = bs(l=12, cls=(aarch64_imm_sft,))

# imm32_3 = bs(l=3, cls=(aarch64_imm_32,))
imm32_3 = bs(l=3, fname="imm")
imm6 = bs(l=6, fname="imm", order=-1)
imm3 = bs(l=3, fname="imm", order=-1)
simm6 = bs(l=6, cls=(aarch64_int64_noarg, m_arg), fname="imm", order=-1)
simm9 = bs(l=9, cls=(aarch64_int64_noarg,), fname="imm", order=-1)
simm7 = bs(l=7, cls=(aarch64_int64_noarg,), fname="imm", order=-1)
nzcv = bs(l=4, cls=(aarch64_uint64_noarg, m_arg), fname="nzcv", order=-1)
uimm5 = bs(l=5, cls=(aarch64_uint64_noarg, m_arg), fname="imm", order=-1)
uimm12 = bs(l=12, cls=(aarch64_uint64_noarg,), fname="imm", order=-1)
uimm16 = bs(l=16, cls=(aarch64_uint64_noarg, m_arg), fname="imm", order=-1)
uimm7 = bs(l=7, cls=(aarch64_uint64_noarg,), fname="imm", order=-1)

uimm8 = bs(l=8, cls=(aarch64_uint64,), fname="imm", order=-1)

op1 = bs(l=3, cls=(aarch64_uint64, m_arg), fname="op1")
op2 = bs(l=3, cls=(aarch64_uint64, m_arg), fname="op2")


imm16 = bs(l=16, fname="imm", order=-1)


immlo = bs(l=2, fname='immlo')
immhip = bs(l=19, cls=(aarch64_immhip_page,))
immhi = bs(l=19, cls=(aarch64_immhi_page,))

option = bs(l=3, fname='option', order=-1)


rm_ext = bs(l=5, cls=(aarch64_gpreg_ext,), fname="rm")
rm_sft = bs(l=5, cls=(aarch64_gpreg_sftimm,), fname="rm")

rm_ext2 = bs(l=5, cls=(aarch64_gpreg_ext2,), fname="rm")
rm_ext2_128 = bs(l=5, cls=(aarch64_gpreg_ext2_128,), fname="rm")


imms = bs(l=6, cls=(aarch64_imm_nsr,), fname='imms')
immr = bs(l=6, fname='immr')
immn = bs(l=1, fname='immn')


imm16_hw = bs(l=16, cls=(aarch64_imm_hw,), fname='imm')
imm16_hw_sc = bs(l=16, cls=(aarch64_imm_hw_sc,), fname='imm')
hw = bs(l=2, fname='hw')


a_imms = bs(l=6, cls=(aarch64_imm_sf, m_arg), fname="imm1", order=-1)
a_immr = bs(l=6, cls=(aarch64_imm_sf, m_arg), fname="imm1", order=-1)



adsu_name = {'ADD': 0, 'SUB': 1}
bs_adsu_name = bs_name(l=1, name=adsu_name)


offs19 = bs(l=19, cls=(aarch64_offs,), fname='off')
offs26 = bs(l=26, cls=(aarch64_offs,), fname='off')
offs14 = bs(l=14, cls=(aarch64_offs,), fname='off')

b40 = bs(l=5, cls=(aarch64_b40,), fname='b40', order=1)

sdsize1 = bs(l=1, fname="size")

sdsize = bs(l=2, fname="size")
opsize = bs(l=2, fname="size")
sd = bs(l=5, cls=(aarch64_simdreg,), fname='sd')

opc = bs(l=1, fname='opc', order=-1)

# add/sub (imm)
aarch64op("addsub", [sf, bs_adsu_name, modf, bs('10001'), shift, imm_sft_12, rn, rd], [rd, rn, imm_sft_12])
aarch64op("cmp", [sf, bs('1'), bs('1'), bs('10001'), shift, imm_sft_12, rn, bs('11111')], [rn, imm_sft_12], alias=True)
aarch64op("cmn", [sf, bs('0'), bs('1'), bs('10001'), shift, imm_sft_12, rn, bs('11111')], [rn, imm_sft_12], alias=True)

aarch64op("adrp", [bs('1'), immlo, bs('10000'), immhip, rd64], [rd64, immhip])
aarch64op("adr",  [bs('0'), immlo, bs('10000'), immhi, rd64], [rd64, immhi])

# add/sub (reg shift)
aarch64op("addsub", [sf, bs_adsu_name, modf, bs('01011'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("cmp", [sf, bs('1'), bs('1'), bs('01011'), shift, bs('0'), rm_sft, imm6, rn, bs('11111')], [rn, rm_sft], alias=True)
# add/sub (reg ext)
aarch64op("addsub", [sf, bs_adsu_name, modf, bs('01011'), bs('00'), bs('1'), rm_ext, option, imm3, rn, rd], [rd, rn, rm_ext])
#aarch64op("cmp",    [sf, bs('1'), bs('1'), bs('01011'), bs('00'), bs('1'), rm_ext, option, imm3, rn, bs('11111')], [rn, rm_ext], alias=True)


aarch64op("neg", [sf, bs('1'), modf, bs('01011'), shift, bs('0'), rm_sft, imm6, bs('11111'), rd], [rd, rm_sft], alias=True)


logic_name = {'AND': 0, 'ORR': 1, 'EOR': 2, 'ANDS': 3}
bs_logic_name = bs_name(l=2, name=logic_name)
# logical (imm)
aarch64op("logic", [sf, bs_logic_name, bs('100100'), immn, immr, imms, rn0, rd], [rd, rn0, imms])

# bitfield move p.149
logicbf_name = {'SBFM': 0b00, 'BFM': 0b01, 'UBFM': 0b10}
bs_logicbf_name = bs_name(l=2, name=logicbf_name)
aarch64op("logic", [sf, bs_logicbf_name, bs('100110'), bs(l=1, cls=(aarch64_eq,), ref="sf"), a_immr, a_imms, rn, rd], [rd, rn, a_immr, a_imms])


# logical (reg shift)
aarch64op("and",  [sf, bs('00'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("bic",  [sf, bs('00'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("orr",  [sf, bs('01'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("orn",  [sf, bs('01'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("mvn",  [sf, bs('01'), bs('01010'), shift, bs('1'), rm_sft, imm6, bs('11111'), rd], [rd, rm_sft], alias=True)
aarch64op("eor",  [sf, bs('10'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("eon",  [sf, bs('10'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("ands", [sf, bs('11'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("tst",  [sf, bs('11'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, bs('11111')], [rn, rm_sft], alias=True)
aarch64op("bics", [sf, bs('11'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])

# move reg
aarch64op("mov",  [sf, bs('01'), bs('01010'), bs('00'), bs('0'), rmz, bs('000000'), bs('11111'), rd], [rd, rmz], alias=True)



bcond = bs_mod_name(l=4, fname='cond', mn_mod=['EQ', 'NE', 'CS', 'CC',
                                               'MI', 'PL', 'VS', 'VC',
                                               'HI', 'LS', 'GE', 'LT',
                                               'GT', 'LE', 'AL', 'NV'])

cond_arg = bs(l=4, cls=(aarch64_cond_arg,), fname=cond)
cond_inv_arg = bs(l=4, cls=(aarch64_cond_inv_arg,), fname=cond)
# unconditional branch (ret)
aarch64op("br", [bs('1101011'), bs('0000'), bs('11111'), bs('000000'), rn64, bs('00000')], [rn64])
aarch64op("blr", [bs('1101011'), bs('0001'), bs('11111'), bs('000000'), rn64, bs('00000')], [rn64])
aarch64op("ret", [bs('1101011'), bs('0010'), bs('11111'), bs('000000'), rn64, bs('00000')], [rn64])
aarch64op("eret", [bs('1101011'), bs('0100'), bs('11111'), bs('000000'), bs('11111'), bs('00000')])
aarch64op("drps", [bs('1101011'), bs('0101'), bs('11111'), bs('000000'), bs('11111'), bs('00000')])

# unconditional branch (imm)
aarch64op("b",  [bs('0'), bs('00101'), offs26], [offs26])
aarch64op("bl", [bs('1'), bs('00101'), offs26], [offs26])


post_pre = bs(l=1, order=-1, fname='postpre')

# conditional compare (imm) p.158
ccmp_name = {'CCMN': 0, 'CCMP': 1}
bs_ccmp_name = bs_name(l=1, name=ccmp_name)
aarch64op("condcmp", [sf, bs_ccmp_name, bs('1'), bs('11010010'), uimm5, cond_arg, bs('1'), bs('0'), rn, bs('0'), nzcv], [rn, uimm5, nzcv, cond_arg])
aarch64op("condcmp", [sf, bs_ccmp_name, bs('1'), bs('11010010'), rm, cond_arg, bs('0'), bs('0'), rn, bs('0'), nzcv], [rn, rm, nzcv, cond_arg])

ldst_b_name = {'STRB': 0, 'LDRB': 1}
bs_ldst_b_name = bs_name(l=1, name=ldst_b_name)
ldst_name = {'STR': 0, 'LDR': 1}
bs_ldst_name = bs_name(l=1, name=ldst_name)
ldst_h_name = {'STRH': 0, 'LDRH': 1}
bs_ldst_h_name = bs_name(l=1, name=ldst_h_name)

ldst_tb_name = {'STTRB': 0, 'LDTRB': 1}
bs_ldst_tb_name = bs_name(l=1, name=ldst_tb_name)

ldst_th_name = {'STTRH': 0, 'LDTRH': 1}
bs_ldst_th_name = bs_name(l=1, name=ldst_th_name)

ldst_ub_name = {'STURB': 0, 'LDURB': 1}
bs_ldst_ub_name = bs_name(l=1, name=ldst_ub_name)
ldst_u_name = {'STUR': 0, 'LDUR': 1}
bs_ldst_u_name = bs_name(l=1, name=ldst_u_name)

ldst_t_name = {'STTR': 0, 'LDTR': 1}
bs_ldst_st_name = bs_name(l=1, name=ldst_t_name)

ldst_1u_name = {'STUR': 0b0, 'LDUR': 0b1}
bs_ldst_1u_name = bs_name(l=1, name=ldst_1u_name)

ldst_uh_name = {'STURH': 0, 'LDURH': 1}
bs_ldst_uh_name = bs_name(l=1, name=ldst_uh_name)


ldst_sw_name = {'STRSW': 0, 'LDRSW': 1}
bs_ldst_sw_name = bs_name(l=1, name=ldst_sw_name)

# load/store register (imm post index)
aarch64op("ldst",   [bs('00'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_b_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldrsb",  [bs('00'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldrsh",  [bs('01'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldst",   [bs('01'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_h_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldst",   [bs('10'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldrsw",  [bs('10'), bs('111'), bs('0'), bs('00'), bs('10'), bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt64], [rt64, rn64_deref ])
aarch64op("ldst",   [bs('11'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt64], [rt64, rn64_deref ])

aarch64op("ldst",   [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, sd], [sd, rn64_deref ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, sd128], [sd128, rn64_deref ])

# load/store register (unsigned imm)
aarch64op("ldst",   [bs('00', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_b_name, uimm12, rn64_deref_sz, rt32], [rt32, rn64_deref_sz ])
aarch64op("ldrsb",  [bs('00', fname="size"), bs('111'), bs('0'), bs('01'), bs('1'), sf, uimm12, rn64_deref_sz, rt_isf], [rt_isf, rn64_deref_sz ])
aarch64op("ldrsh",  [bs('01', fname="size"), bs('111'), bs('0'), bs('01'), bs('1'), sf, uimm12, rn64_deref_sz, rt_isf], [rt_isf, rn64_deref_sz ])
aarch64op("ldst",   [bs('01', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_h_name, uimm12, rn64_deref_sz, rt32], [rt32, rn64_deref_sz ])
aarch64op("ldst",   [bs('10', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_name, uimm12, rn64_deref_sz, rt32], [rt32, rn64_deref_sz ])
aarch64op("ldrsw",  [bs('10', fname="size"), bs('111'), bs('0'), bs('01'), bs('10'), uimm12, rn64_deref_sz, rt64], [rt64, rn64_deref_sz ])
aarch64op("ldst",   [bs('11', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_name, uimm12, rn64_deref_sz, rt64], [rt64, rn64_deref_sz ])

aarch64op("ldst",   [sdsize, bs('111'), bs('1'), bs('01'), bs('0'), bs_ldst_name, uimm12, rn64_deref_sz, sd], [sd, rn64_deref_sz ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('01'), bs('1', fname='size', amount=4), bs_ldst_name, uimm12, rn64_deref_sz, sd128], [sd128, rn64_deref_sz ])

# load/store register (unp)
aarch64op("ldst",   [bs('00'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_tb_name, bs('0'), simm9, bs('10'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldtrsb", [bs('00'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('10'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldtrsh", [bs('01'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('10'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldsttrh",[bs('01'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_th_name, bs('0'), simm9, bs('10'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldtrsw", [bs('10'), bs('111'), bs('0'), bs('00'), bs('10'), bs('0'), simm9, bs('10'), rn64_deref, rt64], [rt64, rn64_deref ])
aarch64op("ldstt",  [bs('1'), sf, bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_st_name, bs('0'), simm9, bs('10'), rn64_deref, rt], [rt, rn64_deref ])

aarch64op("ldstt",  [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_st_name, bs('0'), simm9, bs('10'), rn64_deref, sd], [sd, rn64_deref ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_st_name, bs('0'), simm9, bs('10'), rn64_deref, sd128], [sd128, rn64_deref ])

# load/store register (unscaled imm)
aarch64op("ldst",   [bs('00'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_ub_name, bs('0'), simm9, bs('00'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldursb", [bs('00'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('00'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldstuh", [bs('01'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_uh_name, bs('0'), simm9, bs('00'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldursh", [bs('01'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('00'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldursw", [bs('10'), bs('111'), bs('0'), bs('00'), bs('10'), bs('0'), simm9, bs('00'), rn64_deref, rt64], [rt64, rn64_deref ])
aarch64op("ldst",   [bs('1'), sf, bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_u_name, bs('0'), simm9, bs('00'), rn64_deref, rt], [rt, rn64_deref ])

aarch64op("ldstu",  [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_u_name, bs('0'), simm9, bs('00'), rn64_deref, sd], [sd, rn64_deref ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_1u_name, bs('0'), simm9, bs('00'), rn64_deref, sd128], [sd128, rn64_deref ])

# load/store (register) p.728

aarch64op("ldstrb",[bs('00', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_b_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt32], [rt32, rm_ext2])

aarch64op("ldstrh",[bs('01', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_h_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt32], [rt32, rm_ext2])

aarch64op("ldrsb", [bs('00', fname="size"), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt_isf], [rt_isf, rm_ext2])

aarch64op("ldrsh", [bs('01', fname="size"), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt_isf], [rt_isf, rm_ext2])

aarch64op("ldst",  [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, sd], [sd, rm_ext2])
aarch64op("ldst",  [bs('00', fname="size"), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_name, bs('1'), rm_ext2_128, option, shiftb, bs('10'), rn64_v, sd128], [sd128, rm_ext2_128])

aarch64op("str",   [bs('10', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt32], [rt32, rm_ext2])

aarch64op("ldrsw", [bs('10', fname="size"), bs('111'), bs('0'), bs('00'), bs('10'), bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt64], [rt64, rm_ext2])

aarch64op("ldst",  [bs('11', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt64], [rt64, rm_ext2])

# load/store literal p.137
aarch64op("ldr",  [bs('0'), sf, bs('011'), bs('0'), bs('00'), offs19, rt], [rt, offs19])
aarch64op("ldr",  [bs('10'), bs('011'), bs('0'), bs('00'), offs19, rt64], [rt64, offs19])

# load/store simd literal p.142
aarch64op("ldr",  [sdsize, bs('011'), bs('1'), bs('00'), offs19, sd1], [sd1, offs19])


# move wide p.203
movwide_name = {'MOVN': 0b00, 'MOVZ': 0b10}
bs_movwide_name = bs_name(l=2, name=movwide_name)
# mov wide (imm)
aarch64op("mov", [sf, bs_movwide_name, bs('100101'), hw, imm16_hw, rd], [rd, imm16_hw])
aarch64op("movk", [sf, bs('11'), bs('100101'), hw, imm16_hw_sc, rd], [rd, imm16_hw_sc])

# stp/ldp p.139
ldstp_name = {'STP': 0b0, 'LDP': 0b1}
bs_ldstp_name = bs_name(l=1, name=ldstp_name)
aarch64op("ldstp", [sf, bs('0'), bs('101'), bs('0'), bs('0'), post_pre, bs('1'), bs_ldstp_name, simm7, rt2, rn64_deref_sf, rt], [rt, rt2, rn64_deref_sf])
aarch64op("ldstp", [sf, bs('0'), bs('101'), bs('0'), bs('0'), bs('1'), bs('0'), bs_ldstp_name, simm7, rt2, rn64_deref_sf, rt], [rt, rt2, rn64_deref_sf])

aarch64op("ldstp", [sdsize, bs('101'), bs('1'), bs('0'), post_pre, bs('1'), bs_ldstp_name, uimm7, sd2, rn64_deref_sd, sd1], [sd1, sd2, rn64_deref_sd])
aarch64op("ldstp", [sdsize, bs('101'), bs('1'), bs('0'), bs('1'), bs('0'), bs_ldstp_name, uimm7, sd2, rn64_deref_sd, sd1], [sd1, sd2, rn64_deref_sd])


# data process p.207
datap0_name = {'RBIT': 0b000000, 'REV16': 0b000001,
              'REV': 0b000010,
              'CLZ': 0b000100, 'CLS': 0b000101}
bs_datap0_name = bs_name(l=6, name=datap0_name)
aarch64op("ldstp", [bs('0', fname='sf'), bs('1'), modf, bs('11010110'), bs('00000'), bs_datap0_name, rn, rd])
datap1_name = {'RBIT': 0b000000, 'REV16': 0b000001,
               'REV32': 0b000010, 'REV': 0b000011,
              'CLZ': 0b000100, 'CLS': 0b000101}
bs_datap1_name = bs_name(l=6, name=datap1_name)
aarch64op("ldstp", [bs('1', fname='sf'), bs('1'), modf, bs('11010110'), bs('00000'), bs_datap1_name, rn, rd])


# conditional branch p.132
aarch64op("b.",   [bs('0101010'), bs('0'), offs19, bs('0'), bcond], [offs19])
aarch64op("cbnz", [sf, bs('011010'), bs('1'), offs19, rt], [rt, offs19])
aarch64op("cbz",  [sf, bs('011010'), bs('0'), offs19, rt], [rt, offs19])
aarch64op("tbnz", [sf, bs('011011'), bs('1'), b40, offs14, rt], [rt, b40, offs14])
aarch64op("tbz",  [sf, bs('011011'), bs('0'), b40, offs14, rt], [rt, b40, offs14])


# fmov register p.160
aarch64op("fmov",  [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('00'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])
# fmov scalar imm p.160
aarch64op("fmov",  [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), uimm8, bs('100'), bs('00000'), sdd_32_64], [sdd_32_64, uimm8])
# floating point comparison p.164
aarch64op("fcmp",  [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64_zero, bs('00'), bs('1000'), sdn_32_64, bs('0'), opc, bs('000')], [sdn_32_64, sdm_32_64_zero])
aarch64op("fcmpe", [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64_zero, bs('00'), bs('1000'), sdn_32_64, bs('1'), opc, bs('000')], [sdn_32_64, sdm_32_64_zero])
# floating point convert p.161
aarch64op("fcvtas",[sf, bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('00'), bs('100'), bs('000000'), sdn_32_64, rd], [rd, sdn_32_64])
aarch64op("fcvtzu",[sf, bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('11'), bs('001'), bs('000000'), sdn_32_64, rd], [rd, sdn_32_64])
aarch64op("fcvtzs",[sf, bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('11'), bs('000'), bs('000000'), sdn_32_64, rd], [rd, sdn_32_64])

aarch64op("fcvt",  [bs('000'), bs('11110'), bs('11'), bs('1'), bs('0001'), bs('00'), bs('10000'), sn16, sd32], [sd32, sn16])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('11'), bs('1'), bs('0001'), bs('01'), bs('10000'), sn16, sd64], [sd64, sn16])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('00'), bs('1'), bs('0001'), bs('11'), bs('10000'), sn32, sd16], [sd16, sn32])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('00'), bs('1'), bs('0001'), bs('01'), bs('10000'), sn32, sd64], [sd64, sn32])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('01'), bs('1'), bs('0001'), bs('11'), bs('10000'), sn64, sd16], [sd16, sn64])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('01'), bs('1'), bs('0001'), bs('00'), bs('10000'), sn64, sd32], [sd32, sn64])



swapargs = bs_swapargs(l=1, fname="swap", mn_mod=range(1 << 1))

aarch64op("fmov",  [bs('0'), bs('00'), bs('11110'), bs('00'), bs('1'), bs('00'), bs('110'), bs('000000'), sn32, rd32], [rd32, sn32])
aarch64op("fmov",  [bs('0'), bs('00'), bs('11110'), bs('00'), bs('1'), bs('00'), bs('111'), bs('000000'), rn32, sd32], [sd32, rn32])
aarch64op("fmov",  [bs('1'), bs('00'), bs('11110'), bs('00'), bs('1'), bs('00'), bs('110'), bs('000000'), sd32, rd32], [rd32, sd32])
aarch64op("fmov",  [bs('1'), bs('00'), bs('11110'), bs('01'), bs('1'), bs('00'), bs('111'), bs('000000'), rd64, sd64], [sd64, rd64])
aarch64op("fmov",  [bs('1'), bs('00'), bs('11110'), bs('01'), bs('1'), bs('00'), bs('110'), bs('000000'), sd64, rd64], [rd64, sd64])



# floating point arith p.163
aarch64op("fsub",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('001'), bs('1'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fadd",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('001'), bs('0'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fdiv",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('000'), bs('1'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fmul",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('000'), bs('0'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fnmul", [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('100'), bs('0'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])

aarch64op("fabs",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('01'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])
aarch64op("fneg",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('10'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])
aarch64op("fsqrt", [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('11'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])


# floating point multiply add p.163
aarch64op("fmadd", [bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('0'), sdm_32_64, bs('0'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])
aarch64op("fmsub", [bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('0'), sdm_32_64, bs('1'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])
aarch64op("fnmadd",[bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('0'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])
aarch64op("fnmsub",[bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('1'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])

# convertion float integer p.235
aarch64op("scvtf", [sf, bs('0'), bs('0'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('00'), bs('010'), bs('000000'), rn, sdd_32_64], [sdd_32_64, rn])
aarch64op("ucvtf", [sf, bs('0'), bs('0'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('00'), bs('011'), bs('000000'), rn, sdd_32_64], [sdd_32_64, rn])



# conditional select p.158
aarch64op("csel",  [sf, bs('0'), bs('0'), bs('11010100'), rmz, cond_arg, bs('00'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("csinc", [sf, bs('0'), bs('0'), bs('11010100'), rmz, cond_arg, bs('01'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("csinv", [sf, bs('1'), bs('0'), bs('11010100'), rmz, cond_arg, bs('00'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("csneg", [sf, bs('1'), bs('0'), bs('11010100'), rmz, cond_arg, bs('01'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("cset",  [sf, bs('0'), bs('0'), bs('11010100'), bs('11111'), cond_inv_arg, bs('01'), bs('11111'), rd], [rd, cond_inv_arg], alias=True)
aarch64op("csetm", [sf, bs('1'), bs('0'), bs('11010100'), bs('11111'), cond_inv_arg, bs('00'), bs('11111'), rd], [rd, cond_inv_arg], alias=True)


# multiply p.156
aarch64op("madd",  [sf, bs('00'), bs('11011'), bs('000'), rm, bs('0'), ra, rn, rd], [rd, rn, rm, ra])
aarch64op("msub",  [sf, bs('00'), bs('11011'), bs('000'), rm, bs('1'), ra, rn, rd], [rd, rn, rm, ra])

aarch64op("umulh", [bs('1'), bs('00'), bs('11011'), bs('110'), rm64, bs('0'), bs('11111'), rn64, rd64], [rd64, rn64, rm64])
aarch64op("smulh", [bs('1'), bs('00'), bs('11011'), bs('010'), rm64, bs('0'), bs('11111'), rn64, rd64], [rd64, rn64, rm64])
aarch64op("umsubh",[bs('1'), bs('00'), bs('11011'), bs('101'), rm32, bs('1'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])


aarch64op("smaddl",[bs('1'), bs('00'), bs('11011'), bs('001'), rm32, bs('0'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])
aarch64op("umaddl",[bs('1'), bs('00'), bs('11011'), bs('101'), rm32, bs('0'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])

aarch64op("smsubl",[bs('1'), bs('00'), bs('11011'), bs('001'), rm32, bs('1'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])
aarch64op("umsubl",[bs('1'), bs('00'), bs('11011'), bs('101'), rm32, bs('1'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])

# division p.156
aarch64op("sdiv", [sf, bs('0'), bs('0'), bs('11010110'), rm, bs('00001'), bs('1'), rn, rd], [rd, rn, rm])
aarch64op("udiv", [sf, bs('0'), bs('0'), bs('11010110'), rm, bs('00001'), bs('0'), rn, rd], [rd, rn, rm])


# extract register p.150
aarch64op("extr", [sf, bs('00100111'), bs(l=1, cls=(aarch64_eq,), ref="sf"), bs('0'), rm, simm6, rn, rd], [rd, rn, rm, simm6])

# shift reg p.155
shiftr_name = {'LSL': 0b00, 'LSR': 0b01, 'ASR': 0b10, 'ROR': 0b11}
bs_shiftr_name = bs_name(l=2, name=shiftr_name)

aarch64op("shiftr", [sf, bs('0'), bs('0'), bs('11010110'), rm, bs('0010'), bs_shiftr_name, rn, rd], [rd, rn, rm])

#
aarch64op("NOP", [bs('11010101000000110010000000011111')])

# exception p.133
aarch64op("brk", [bs('11010100'), bs('001'), uimm16, bs('000'), bs('00')], [uimm16])
aarch64op("hlt", [bs('11010100'), bs('010'), uimm16, bs('000'), bs('00')], [uimm16])
aarch64op("svc", [bs('11010100'), bs('000'), uimm16, bs('000'), bs('01')], [uimm16])
aarch64op("hvc", [bs('11010100'), bs('000'), uimm16, bs('000'), bs('10')], [uimm16])
aarch64op("smc", [bs('11010100'), bs('000'), uimm16, bs('000'), bs('11')], [uimm16])

# msr p.631
msr_name = {'MSR': 0b0, 'MRS': 0b1}
bs_msr_name = bs_name(l=1, name=msr_name)
aarch64op("mrs", [bs('1101010100'), bs('1'), bs('1'), bs('1'), op1, crn, crm, op2, rt64], [rt64, op1, crn, crm, op2])
aarch64op("msr", [bs('1101010100'), bs('0'), bs('1'), bs('1'), op1, crn, crm, op2, rt64], [op1, crn, crm, op2, rt64])

# load/store exclusive p.140
aarch64op("stxr", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('0'), bs('11111'), rn64_deref_nooff, rt], [rs32, rt, rn64_deref_nooff])
aarch64op("ldxr", [bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('0'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])


aarch64op("stxrb", [bs('0'), bs('0'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("ldxrb", [bs('0'), bs('0'), bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])

aarch64op("stxrb", [bs('0'), bs('1'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("ldxrh", [bs('0'), bs('1'), bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])

aarch64op("stxp", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('1'), rs32, bs('0'), rt2, rn64_deref_nooff, rt], [rs32, rt, rt2, rn64_deref_nooff])
aarch64op("ldxp", [bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('1'), bs('11111'), bs('0'), rt2, rn64_deref_nooff, rt], [rt, rt2, rn64_deref_nooff])

# load acquire/store release p.141
aarch64op("ldar", [bs('1'), sf, bs('001000'), bs('1'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("ldarb",[bs('0'), bs('0'), bs('001000'), bs('1'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("ldarh",[bs('0'), bs('1'), bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("ldaxp",[bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('1'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("ldaxr",[bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])

aarch64op("stlxr", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('1'), bs('11111'), rn64_deref_nooff, rt], [rs32, rt, rn64_deref_nooff])
aarch64op("stlxrb",[bs('0'), bs('0'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("stlxrh",[bs('0'), bs('1'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("stlxp", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('1'), rs32, bs('1'), rt2, rn64_deref_nooff, rt], [rs32, rt, rt2, rn64_deref_nooff])

# barriers p.135
aarch64op("dsb", [bs('1101010100'), bs('0000110011'), crm, bs('1'), bs('00'), bs('11111')], [crm])
aarch64op("dmb", [bs('1101010100'), bs('0000110011'), crm, bs('1'), bs('01'), bs('11111')], [crm])
aarch64op("isb", [bs('1101010100'), bs('0000110011'), crm, bs('1'), bs('10'), bs('11111')], [crm])