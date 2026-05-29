import gdb
import subprocess
import re
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
header_path = os.path.normpath(os.path.join(script_dir, "../src/include/gsreldata.h"))
compartiment_list = ["Monitor", "Application"]

def get_page_head():
    gs_base = gdb.parse_and_eval("$gs_base")
    with open(header_path, "r") as f:
        for line in f:
            m = re.match(r"#define\s+PAGES_HEAD_OFFSET\s+(\S+)", line)
            if m:
                page_head_offset = int(m.group(1), 0)
                break

    page_head_addr = gs_base+page_head_offset
    virt_page_type = gdb.lookup_type("struct virt_page")
    virt_page_ptr_type = virt_page_type.pointer()
    virt_page_ptr_ptr_type = virt_page_ptr_type.pointer()
    virt_page_ptr_ptr_ptr_type = virt_page_ptr_ptr_type.pointer()

    head_ptr = gdb.Value(page_head_addr).cast(virt_page_ptr_ptr_ptr_type)

    if not head_ptr.dereference():
        return 0
    
    return head_ptr.dereference().dereference()

def print_page(addr):
    page = addr.dereference()
    start = int(page["start"])
    size  = int(page["size"])
    prot  = int(page["prot"])
    cid   = int(page["Cid"])
    nextp = page["next"]
    prot_str = list("---")
    if prot & 1:
        prot_str[0] = "r"
    if prot & 2:
        prot_str[1] = "w"
    if prot & 4:
        prot_str[2] = "x"
    prot_str = "".join(prot_str)
    end = start + size

    print(f"{start:#x}-{end:#x}({size:#x}) {prot_str} [{compartiment_list[cid]}]")

    return nextp


def print_mem():
    head = get_page_head()
    if not head:
        print("head not found")
        return
    while head:
        head = print_page(head)
    return

def get_mem(addr):
    head = get_page_head()
    if not head:
        print("head not found")
        return
    while head:
        page = head.dereference()
        start = int(page["start"])
        size  = int(page["size"])
        end   = start + size
        if start <= addr < end:
            print_page(head)
            return head
        head = page["next"]

    print(f"address {addr:#x} not found")
    return None
    
