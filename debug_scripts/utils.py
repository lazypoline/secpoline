import gdb
import subprocess
import re

def _get_linux_tid():
    try:
        ptid = gdb.selected_thread().ptid
        # ptid = (pid, lwpid, tid)
        return ptid[1] if ptid[1] != 0 else ptid[0]
    except Exception:
        return None
    
def load_all_symbols(flags):
    vebose = False
    if (len(flags)>0) and flags[0] == "-v":
        vebose = True
    found_file = []
    try:
        output = gdb.execute('info proc mappings', to_string=True)
    except gdb.error:
        print("Not running or info proc mappings not supported.")
        return
        
    lines = output.splitlines()
    current_file = ""
    for line in lines:
        info = line.strip().split()
        if(len(info) != 6):
            current_file = ""
            continue
        start_address = info[0]
        perms = info[4]
        file = info[5]
        if(file == current_file or file[0] != "/" or perms != "r--p"):
            if(file[0] != "/"):
                current_file = ""
            continue
        found_file.append(file)
        current_file = file
        try:
            cmd = f"readelf -WS {file} | grep '\\.text' | awk '{{ print \"0x\"$5 }}'"
            text_offset = subprocess.check_output(cmd, shell=True, text=True).strip()
            text_addr = int(start_address, 16) + int(text_offset, 16)
            gdb.execute(f"add-symbol-file {file} 0x{text_addr:x}", to_string=True)
        except Exception as e:
            print(f"Failed for {file}: {e}")
    print("loaded in all symbols")
    if vebose:
        for f in found_file:
            print(f)


def parse_hex_field(text, field):
    m = re.search(rf"^{field}:\s*([0-9A-Fa-f]+)", text, re.MULTILINE)
    if not m:
        return 0
    return int(m.group(1), 16)

def get_linux_tid():
    try:
        ptid = gdb.selected_thread().ptid
        return ptid[1] if ptid[1] != 0 else ptid[0]
    except Exception:
        return None


def signal_status(signum):
    inferior = gdb.selected_inferior()
    if inferior.pid is None:
        return

    tid = get_linux_tid()
    if tid is None:
        return

    status_path = f"/proc/{inferior.pid}/task/{tid}/status"

    try:
        with open(status_path) as f:
            status = f.read()
    except Exception as e:
        print(f"[safe_handle_sig] Could not read {status_path}: {e}")
        return

    sigblk = parse_hex_field(status, "SigBlk")
    sigcgt = parse_hex_field(status, "SigCgt")

    mask = 1 << (signum - 1)

    is_blocked = (sigblk & mask) != 0
    has_handler = (sigcgt & mask) != 0
    return (is_blocked, has_handler)

