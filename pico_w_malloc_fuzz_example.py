#!/usr/bin/env python3
import os
import signal
import sys
import logging
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
import unicornafl
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

BINARY_PATH = "malloc_example.elf"
STACK_ADDR = 0x40000000
STACK_SIZE = 0x10000
INPUT_ADDR = 0x21000000
INPUT_SIZE = 0x1000
PAGE_SIZE = 0x1000
HEAP_ADDR = 0x30000000
HEAP_SIZE = 0x100000  # 1MB heap
ALLOC_SPACING = 0x1000  # Reserved space to catch OOB access


target_func_addr = None # Start
return_addr = None      # Stop

# Initialize Capstone for disassembly
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# HeapManager is used to detect OOB heap memory access
class HeapManager:
    def __init__(self, uc):
        self.uc = uc
        self.next_addr = HEAP_ADDR
        self.allocations = {}  # addr -> size mapping
        
    def malloc(self, size):
        if size <= 0:
            return 0
            
        # Check if we have enough space
        if self.next_addr + size + ALLOC_SPACING > HEAP_ADDR + HEAP_SIZE:
            debug("Out of heap memory")
            return 0
            
        addr = self.next_addr
        self.allocations[addr] = size
        debug("Allocated %d bytes at 0x%x", size, addr)
        
        # Reserve space between allocations to catch OOB access
        self.next_addr = addr + size + ALLOC_SPACING
        return addr
        
    def free(self, addr):
        if addr == 0:
            return
            
        if addr not in self.allocations:
            debug("Invalid free of address 0x%x", addr)
            os.kill(os.getpid(), signal.SIGSEGV)
            return
            
        debug("Freed allocation at 0x%x", addr)
        del self.allocations[addr]
        
    def check_access(self, addr, size, is_write):
        # Find if address falls within any allocation
        for alloc_addr, alloc_size in self.allocations.items():
            if alloc_addr <= addr < alloc_addr + alloc_size:
                # Check if access extends beyond allocation
                if addr + size > alloc_addr + alloc_size:
                    debug("%s overflow detected at 0x%x", "Write" if is_write else "Read", addr)
                    return False
                return True
                
        debug("Invalid %s access at 0x%x", "write" if is_write else "read", addr)
        return False

def hook_mem_access(uc, access, address, size, value, user_data):
    heap = user_data
    if HEAP_ADDR <= address < HEAP_ADDR + HEAP_SIZE:
        if not heap.check_access(address, size, access == UC_HOOK_MEM_WRITE):
            # Invalid access, signal crash to AFL
            debug("Unsafe memory access detected at 0x%x, crashing...", address)
            os.kill(os.getpid(), signal.SIGSEGV)
            return True
    return True

def hook_code(uc, address, size, user_data):
    debug("Executing @ 0x%08x (size=%d)", address, size)
    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        instruction_bytes = uc.mem_read(address, size)
        for insn in cs.disasm(instruction_bytes, address):
            debug("\tInstruction: %s %s", insn.mnemonic, insn.op_str)
    return True

def malloc_hook(uc, heap):
    size = uc.reg_read(UC_ARM_REG_R0)
    addr = heap.malloc(size)
    uc.reg_write(UC_ARM_REG_R0, addr)
    debug("malloc(%d) = 0x%x", size, addr)

def free_hook(uc, heap):
    addr = uc.reg_read(UC_ARM_REG_R0)
    heap.free(addr)
    debug("free(0x%x)", addr)

def memcpy_hook(uc, heap):
    dst = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    size = uc.reg_read(UC_ARM_REG_R2)
    
    debug("memcpy(dst=0x%x, src=0x%x, size=%d, size_type=%s)", dst, src, size, type(size))
    
    try:
        data = uc.mem_read(src, int(size))
        uc.mem_write(dst, bytes(data))
    except Exception as e:
        debug("memcpy: Memory access error: %s", str(e))
        debug("size type: %s, value: %r", type(size), size)
        os.kill(os.getpid(), signal.SIGSEGV)
        return
    
    # Set return value to destination address (per memcpy spec)
    uc.reg_write(UC_ARM_REG_R0, dst)

def setup_hooks(uc):
    # Create heap manager
    heap = HeapManager(uc)
    
    # Hook memory access for heap protection
    uc.hook_add(UC_HOOK_MEM_READ, hook_mem_access, user_data=heap)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access, user_data=heap)
    
    # Get function addresses
    try:
        malloc_addr = get_function_address(BINARY_PATH, '__wrap_malloc') - 1  # Subtract 1 for Thumb mode
        free_addr = get_function_address(BINARY_PATH, '__wrap_free') - 1  # Subtract 1 for Thumb mode
        memcpy_addr = get_function_address(BINARY_PATH, '__wrap_memcpy') - 1  # Subtract 1 for Thumb mode
        gpio_set_addr = get_function_address(BINARY_PATH, 'cyw43_gpio_set') - 1  # Subtract 1 for Thumb mode
        sleep_ms_addr = get_function_address(BINARY_PATH, 'sleep_ms') - 1  # Subtract 1 for Thumb mode
        logging.info("Found __wrap_malloc @ 0x%x", malloc_addr)
        logging.info("Found __wrap_free @ 0x%x", free_addr)
        logging.info("Found __wrap_memcpy @ 0x%x", memcpy_addr)
        logging.info("Found cyw43_gpio_set @ 0x%x", gpio_set_addr)
        logging.info("Found sleep_ms @ 0x%x", sleep_ms_addr)
    except Exception as e:
        logging.error("Failed to find required functions: %s", e)
        sys.exit(1)
    
    # Hook malloc, free, and memcpy with internal implementations
    def hook_malloc_wrapper(uc, address, size, user_data):
        malloc_hook(uc, heap)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        
    def hook_free_wrapper(uc, address, size, user_data):
        free_hook(uc, heap)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            
    def hook_memcpy_wrapper(uc, address, size, user_data):
        memcpy_hook(uc, heap)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    # Skip over cyw43_gpio_set and sleep_ms
    def hook_gpio_set_wrapper(uc, address, size, user_data):
        debug("Skipping cyw43_gpio_set(gpio=%d, value=%d)", 
              uc.reg_read(UC_ARM_REG_R0), 
              uc.reg_read(UC_ARM_REG_R1))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def hook_sleep_ms_wrapper(uc, address, size, user_data):
        debug("Skipping sleep_ms(%d)", uc.reg_read(UC_ARM_REG_R0))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    
    uc.hook_add(UC_HOOK_CODE, hook_malloc_wrapper, begin=malloc_addr, end=malloc_addr+2)
    uc.hook_add(UC_HOOK_CODE, hook_free_wrapper, begin=free_addr, end=free_addr+2)
    uc.hook_add(UC_HOOK_CODE, hook_memcpy_wrapper, begin=memcpy_addr, end=memcpy_addr+2)
    uc.hook_add(UC_HOOK_CODE, hook_gpio_set_wrapper, begin=gpio_set_addr, end=gpio_set_addr+2)
    uc.hook_add(UC_HOOK_CODE, hook_sleep_ms_wrapper, begin=sleep_ms_addr, end=sleep_ms_addr+2)

def setup_logging():
    level = logging.DEBUG if os.getenv("AFL_DEBUG", "0") == "1" else logging.INFO
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=level)


def debug(msg, *args):
    logging.debug(msg, *args)


def get_function_address(elf_path, func_name):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name('.symtab')
        if not symtab:
            raise RuntimeError(f"Symbol table not found in {elf_path}")
        symbols = symtab.get_symbol_by_name(func_name)
        if not symbols:
            raise RuntimeError(f"Function '{func_name}' not found in {elf_path}")
        return symbols[0]['st_value']


def find_return_address(elf_path, func_addr):
    """
    Find the first return instruction (either 'bx lr' or 'pop {..., pc}') after func_addr in the .text section.
    Returns the virtual address of the instruction.
    """
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        text_sec = elffile.get_section_by_name('.text')
        if not isinstance(text_sec, Section):
            raise RuntimeError(".text section not found in ELF")
        
        base = text_sec['sh_addr']
        data = text_sec.data()
        start_offset = func_addr - base - 1
        
        section_data = data[start_offset:]
        current_addr = func_addr & ~1  # Clear thumb bit if set
        
        try:
            for insn in cs.disasm(section_data, current_addr):
                if (insn.mnemonic == "bx" and insn.op_str == "lr") or (insn.mnemonic == "pop" and "pc" in insn.op_str.lower()):
                    debug("Found exit at 0x%x", insn.address)
                    return insn.address
                    
        except Exception as e:
            debug("Disassembly error: %s", str(e))
            
        raise RuntimeError(f"No return instruction found after 0x{func_addr:08x}")


def load_elf_segments(uc, elf_path):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        for seg in elffile.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue

            vaddr = seg['p_vaddr']
            memsz = seg['p_memsz']
            filesz = seg['p_filesz']
            offset = seg['p_offset']

            aligned_vaddr = vaddr & ~(PAGE_SIZE - 1)
            offset_in_page = vaddr - aligned_vaddr
            aligned_size = ((offset_in_page + memsz + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

            perms = 0
            if seg['p_flags'] & 1:
                perms |= UC_PROT_EXEC
            if seg['p_flags'] & 2:
                perms |= UC_PROT_WRITE
            if seg['p_flags'] & 4:
                perms |= UC_PROT_READ

            try:
                uc.mem_map(aligned_vaddr, aligned_size, perms)
                debug("Mapped segment: addr=0x%08x size=0x%x perms=%d", aligned_vaddr, aligned_size, perms)
                f.seek(offset)
                uc.mem_write(vaddr, f.read(filesz))
            except Exception as e:
                debug("Failed mapping at 0x%08x: %s", aligned_vaddr, e)


def place_input(uc, input_data, _index, _data):
    debug("Injecting input (%d bytes)", len(input_data))
    uc.mem_write(INPUT_ADDR, input_data)
    uc.reg_write(UC_ARM_REG_R0, INPUT_ADDR)
    uc.reg_write(UC_ARM_REG_R1, len(input_data))
    uc.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE - 0x10)
    uc.reg_write(UC_ARM_REG_PC, target_func_addr | 1)
    return True

def main():
    setup_logging()

    if len(sys.argv) != 2:
        logging.error("Usage: %s <afl_input_file>", sys.argv[0])
        sys.exit(1)

    afl_input = sys.argv[1]
    global target_func_addr, return_addr

    target_func_addr = get_function_address(BINARY_PATH, 'process_payload')
    logging.info("Function 'process_payload' @ 0x%08x", target_func_addr)

    # Determine where to stop the fuzz
    try:
        return_addr = find_return_address(BINARY_PATH, target_func_addr)
        logging.info("Identified return @ 0x%08x", return_addr)
    except Exception as e:
        logging.error("Exception finding exit: %s", e)
        sys.exit(1)

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.hook_add(UC_HOOK_CODE, hook_code)

    load_elf_segments(uc, BINARY_PATH)
    uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(INPUT_ADDR, INPUT_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(HEAP_ADDR, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    
    # Setup malloc/free hooks and heap protection
    setup_hooks(uc)

    exits = [return_addr]

    logging.info("Starting AFL loop starting @ 0x%08x with exit @ 0x%08x", target_func_addr, return_addr)
    unicornafl.uc_afl_fuzz(
        uc,
        afl_input,
        place_input,
        exits
    )


if __name__ == '__main__':
    main()
