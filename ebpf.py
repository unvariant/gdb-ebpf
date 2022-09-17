import enum
import gdb

def to_str (n) -> str:
    if type(n) == int:
        return hex(n)
    else:
        return str(n)

class Program:
    def __init__ (self, addr: int):
        p = gdb.inferiors()[0]
        self.len = int.from_bytes(p.read_memory(addr, 2).tobytes(), "little")
        self.prog_addr = int.from_bytes(p.read_memory(addr + 8, 8).tobytes(), "little")
        self.max = (self.len - 1) * 8 + 7
        self.buffer = bytes()
        
        for i in range(self.len):
            self.buffer += p.read_memory(self.prog_addr + i * 8, 8).tobytes()

        self.buffer += b'\x00' * 7

    def read (self, pc: int) -> int:
        if pc > self.max:
            return 0
        else:
            return int.from_bytes(self.buffer[pc:pc+8], "little")

class EBPFEnum (enum.Enum):
    def __str__ (self) -> str:
        return self.name[5:]

class Size (EBPFEnum):
    ebpf_word = 0x00
    ebpf_hword = 0x01
    ebpf_byte = 0x02
    ebpf_dword = 0x03

class Register (EBPFEnum):
    ebpf_R0 = 0
    ebpf_R1 = 1
    ebpf_R2 = 2
    ebpf_R3 = 3
    ebpf_R4 = 4
    ebpf_R5 = 5
    ebpf_R6 = 6
    ebpf_R7 = 7
    ebpf_R8 = 8
    ebpf_R9 = 9
    ebpf_R10 = 10

class Type (EBPFEnum):
    ebpf_ld = 0
    ebpf_ldx = 1
    ebpf_st = 2
    ebpf_stx = 3
    ebpf_alu32 = 4
    ebpf_jmp64 = 5
    ebpf_jmp32 = 6
    ebpf_alu64 = 7

class Encoding:
    def __init__ (self, dword: int):
        self.type = Type(dword & 0b111)
        self.opcode = dword & 0xFF
        self.dst = Register((dword >> 0x08) & 0x0F)
        self.src = Register((dword >> 0x0C) & 0x0F)
        self.offset = (dword >> 0x10) & 0xFFFF
        self.imm = dword >> 0x20

class IllegalInstruction(Exception): pass

class Instruction:
    def assemble (self, pc: int) -> str: pass

    def length (self) -> int: return 8

class ALU (Instruction):
    def __init__ (self, encoding: Encoding):
        opcode = encoding.opcode
        source = self.Source(opcode >> 3 & 1)
    
        self.code = self.Code(opcode >> 4)
        self.type = encoding.type

        if source == self.Source.ebpf_k:
            self.dst = encoding.dst
            self.src = encoding.imm
        else:
            self.dst = encoding.dst
            self.src = encoding.src

    def assemble (self, _) -> str:
        mode = ''
        if self.code == self.Code.bswap:
            if self.source == self.source.ebpf_k:
                mode = ".LE"
            else:
                mode = ".BE"
        instr = str(self.code)
        return f"{instr}{mode} {to_str(self.dst)}, {to_str(self.src)}"

    class Source (EBPFEnum):
        ebpf_k = 0x00
        ebpf_x = 0x01

    class Code (EBPFEnum):
        ebpf_add = 0x00
        ebpf_sub = 0x01
        ebpf_mul = 0x02
        ebpf_div = 0x03
        ebpf_orr = 0x04
        ebpf_and = 0x05
        ebpf_shl = 0x06
        ebpf_shr = 0x07
        ebpf_neg = 0x08
        ebpf_mod = 0x09
        ebpf_xor = 0x0A
        ebpf_mov = 0x0B
        ebpf_asr = 0x0C
        ebpf_bswap = 0x0D

class Jmp (Instruction):
    def __init__ (self, encoding: Encoding):
        opcode = encoding.opcode
        source = self.Source(opcode >> 3 & 1)
    
        self.code = self.Code(opcode >> 4)
        self.type = encoding.type
        self.offset = encoding.offset
        self.target = None

        if source == self.Source.ebpf_k:
            self.args = (encoding.src, encoding.imm)
        else:
            self.args = (encoding.dst, encoding.src)

        if self.code in (self.Code.ebpf_call, self.Code.ebpf_jmp, self.Code.ebpf_exit):
            self.args = None
            
        if self.code == self.Code.ebpf_exit:
            self.offset = None

    def assemble (self, pc: int) -> str:
        instr = str(self.code)
        args = list()

        if self.args != None:
            args = [arg for arg in self.args]
        if self.offset != None:
            self.target = pc + self.offset * 8
            args.append(self.target)
        return f"{instr} {', '.join(map(to_str, args))}"

    class Source (EBPFEnum):
        ebpf_k = 0x00
        ebpf_x = 0x01

    class Code (EBPFEnum):
        ebpf_jmp = 0x0
        ebpf_jeq = 0x1
        ebpf_jgt = 0x2
        ebpf_jge = 0x3
        ebpf_jset = 0x4
        ebpf_jne = 0x5
        ebpf_jsgt = 0x6
        ebpf_jsge = 0x7
        ebpf_call = 0x8
        ebpf_exit = 0x9
        ebpf_jlt = 0xA
        ebpf_jle = 0xB
        ebpf_jslt = 0xC
        ebpf_jsle = 0xD

class Memory (Instruction):
    def __init__ (self, encoding: Encoding, next_dword: int):
        opcode = encoding.opcode

        self.code = encoding.type
        self.size = Size(opcode >> 3 & 0b11)
        self.mode = self.Mode(opcode >> 5)
        self.args = list()

        if self.code == Type.ebpf_ldx:
            if self.mode == self.Mode.ebpf_mem:
                self.dst = encoding.dst
                self.args += [encoding.src, self.offset]
            else:
                raise IllegalInstruction
        elif self.code == Type.ebpf_ld:
            if self.mode == self.Mode.ebpf_imm:
                self.code = self.Code.ebpf_mov
                self.dst = encoding.dst
                self.args.append(next_dword)
            elif self.mode in (self.Mode.ebpf_abs, self.Mode.ebpf_ind):
                if self.mode == self.Mode.ebpf_abs:
                    self.code = self.Code.ebpf_ldabs
                else:
                    self.code = self.Code.ebpf_ldind
                self.dst = Register.ebpf_R0
                self.args.append(f"((struct sk_buff *) {to_str(Register.ebpf_R6)})->data")
                if self.mode == self.Mode.ebpf_ind:
                    self.args.append(encoding.src)
                self.args.append(encoding.imm)
            else:
                raise IllegalInstruction
        elif self.code == Type.ebpf_stx:
            if self.mode in (self.Mode.ebpf_mem, self.Mode.ebpf_atomic):
                if self.mode == self.Mode.ebpf_atomic:
                    assert self.size in (Size.ebpf_word, Size.ebpf_dword)
                    try:
                        # complex atomics must have EBPF_FETCH set
                        # and are guaranteed to be caught in the try block
                        self.code = self.AtomicCode(encoding.imm)
                    except:
                        # for simple atomics EBPF_FETCH is optional
                        # if the first attempt to cast fails
                        # remove EBPF_FETCH and try again
                        self.code = self.AtomicCode(encoding.imm & ~0x01)
                self.dst = encoding.src
                self.args += [encoding.dst, encoding.offset]
            else:
                raise IllegalInstruction
        elif self.code == Type.ebpf_st:
            assert self.code == Type.ebpf_st
            self.dst = encoding.imm
            self.args += [encoding.dst, encoding.offset]
        else:
            raise IllegalInstruction

    def assemble (self, _) -> str:                
        size = str(self.size)
        instr = str(self.code)
        dst = to_str(self.dst)

        return f"{instr} {dst}, {size} [{' + '.join(map(to_str, self.args))}]"

    def length (self) -> int:
        if self.mode == self.Mode.ebpf_imm:
            return 16
        else:
            return 8

    class Mode (EBPFEnum):
        ebpf_imm = 0x00
        ebpf_abs = 0x01
        ebpf_ind = 0x02
        ebpf_mem = 0x03
        ebpf_atomic = 0x04

    class Code (EBPFEnum):
        ebpf_mov = 0x00
        ebpf_ldabs = 0x01
        ebpf_ldind = 0x02

    class AtomicCode (EBPFEnum):
        ebpf_add = 0x00
        ebpf_fetch = 0x01
        ebpf_orr = 0x40
        ebpf_and = 0x50
        ebpf_xor = 0xA0
        ebpf_xchg = 0xe1
        ebpf_cmpxchg = 0xf1    

class Bad (Instruction):
    def assemble (self, _) -> str:
        return "(bad)"

class EBPFDecompiler(gdb.Command):
    def __init__ (self):
        gdb.Command.__init__(self, "ebpf"
                             , gdb.COMMAND_USER
                             , gdb.COMPLETE_SYMBOL
                             , gdb.COMPLETE_EXPRESSION
                            )
        self.pc = None
        self.prog = None

    def invoke (self, arg: str, from_tty: bool) -> None:
        n = int(gdb.parse_and_eval(arg))
        self.prog = Program(n)
        disasm = self.decompile()
        
        lines = [f"\t\x1B[34m0x{hex(line[0])[2:].rjust(8, '0')}\x1B[m:\t{line[1]}" for line in disasm]
                
        print('\n'.join(lines))

    def decompile (self) -> list:
        instrs = list()
        
        self.pc = 0

        for _ in range(self.prog.len):
            instr = self.instruction()
            old = self.pc
            self.pc += instr.length()
            instrs.append((old, instr.assemble(self.pc)))

        return instrs

    def instruction (self) -> Instruction:
        try:
            dword = self.prog.read(self.pc)
            next_dword = self.prog.read(self.pc + 8)
            encoding = Encoding(dword)
            if encoding.type in (Type.ebpf_ld, Type.ebpf_ldx, Type.ebpf_st, Type.ebpf_stx):
                return Memory(encoding, next_dword)
            elif encoding.type in (Type.ebpf_alu32, Type.ebpf_alu64):
                return ALU(encoding)
            elif encoding.type in (Type.ebpf_jmp32, Type.ebpf_jmp64):
                return Jmp(encoding)
            else:
                raise IllegalInstruction
        except:
            return Bad()

EBPFDecompiler()