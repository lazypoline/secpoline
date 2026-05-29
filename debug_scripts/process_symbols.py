import gdb
import signal
import re
import os
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)
import utils
import virt_pages

# Helper to decode bitmasks into signal names
def get_signal_names(mask_hex):
    mask = int(mask_hex, 16)
    found = []
    # Standard signals are 1-31, Real-time are 32-64
    for i in range(1, 32):
        if (mask >> (i - 1)) & 1:
            try:
                # Map signum to name (e.g., 2 -> SIGINT)
                found.append(signal.Signals(i).name)
            except ValueError:
                found.append(f"SIGRT_{i}")
    return found

class InfoBlocked(gdb.Command):
    """Print the names of signals that are currently blocked (Signal Mask)."""
    def __init__(self):
        super(InfoBlocked, self).__init__("blocked-sig", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        pid = gdb.selected_inferior().pid
        if pid == 0:
            print("Process not running.")
            return
        
        tid = utils._get_linux_tid()
        if tid is None:
            print("thread not running.")
            return
        
        with open(f"/proc/{pid}/task/{tid}/status") as f:
            for line in f:
                if line.startswith("SigBlk:"):
                    mask_hex = line.split()[1]
                    names = get_signal_names(mask_hex)
                    print(f"Blocked Signals: {', '.join(names) if names else 'None'}")

class InfoHandlers(gdb.Command):
    """Print the names of signals with a custom handler installed."""
    def __init__(self):
        super(InfoHandlers, self).__init__("handled-sig", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        pid = gdb.selected_inferior().pid
        if pid == 0:
            print("Process not running.")
            return
    
        tid = utils._get_linux_tid()
        if tid is None:
            print("thread not running.")
            return
        
        with open(f"/proc/{pid}/task/{tid}/status") as f:
            for line in f:
                if line.startswith("SigCgt:"):
                    mask_hex = line.split()[1]
                    names = get_signal_names(mask_hex)
                    print(f"Signals with Handlers: {', '.join(names) if names else 'None (All Default/Ignored)'}")


class UContext(gdb.Command):
    def __init__(self):
        super(UContext, self).__init__("ucontext", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            argv = gdb.string_to_argv(arg)
            if len(argv) != 2:
                print("Usage: ucontext <address> <reg>")
                return

            address = argv[0]
            reg = argv[1].upper()

            # Evaluate the expression directly in gdb
            expr = f"(unsigned long)((ucontext_t*){address})->uc_mcontext.gregs[REG_{reg}]"
            value = int(gdb.parse_and_eval(expr))
            print(f"{reg} = 0x{value:x}")

        except Exception as e:
            print(f"Error: {e}")

    
class SafeHandleSig(gdb.Command):
    def __init__(self):
        super(SafeHandleSig, self).__init__("safe_handle_sig",
                                            gdb.COMMAND_USER)
        self.watched = set()
        gdb.events.stop.connect(self._on_stop)

    def invoke(self, arg, from_tty):
        sig_name = arg.strip()
        if not sig_name:
            print("Usage: safe_handle_sig SIGNAL_NAME")
            return

        if not sig_name.startswith("SIG"):
            print("Signal must be in form SIGXXX")
            return

        try:
            signum = getattr(signal, sig_name)
        except AttributeError:
            print(f"Unknown signal: {sig_name}")
            return

        self.watched.add(signum)

        # Configure gdb to pass the signal to the program
        gdb.execute(f"handle {sig_name} stop print pass")

    def _on_stop(self, event):
        if not isinstance(event, gdb.SignalEvent):
            return

        sig_name = event.stop_signal

        try:
            signum = getattr(signal, sig_name)
        except AttributeError:
            return

        if signum not in self.watched:
            return

        (is_blocked, has_handler) = utils.signal_status(signum)

        if is_blocked or not has_handler:
            #This cause here seems to be wrong, when SIGSYS is blocked, it seems that info proc status is showing that there is no handler and that it is not blocked even when it is the other way around
            #print(f"[safe_handle_sig] {sig_name}: blocked={is_blocked}, handler={has_handler}")
            print(f"[safe_handle_sig] Pausing on {sig_name}")
            utils.load_all_symbols(["-v"])
            return

        # IMPORTANT: defer continue to avoid recursion
        gdb.post_event(lambda: gdb.execute("continue"))


class add_symbols_auto(gdb.Command):
    def __init__(self):
        super(add_symbols_auto, self).__init__('asa', gdb.COMMAND_USER, gdb.COMPLETE_FILENAME)
    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        utils.load_all_symbols(argv)
            
class PrintSiginfo(gdb.Command):
    def __init__(self):
        super(PrintSiginfo, self).__init__("siginfo",gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        arg = arg.strip()
        if not arg:
            print("Usage: siginfo ADDRESS")
            return

        try:
            addr = int(gdb.parse_and_eval(arg))
        except Exception:
            print("Invalid address.")
            return

        # Get the fully defined internal siginfo type from $_siginfo
        try:
            siginfo_val = gdb.parse_and_eval("$_siginfo")
        except Exception:
            print("$_siginfo not available (no signal stop?)")
            return

        siginfo_type = siginfo_val.type

        # Cast pointer to correct type
        ptr_type = siginfo_type.pointer()
        siginfo_ptr = gdb.Value(addr).cast(ptr_type)

        # Dereference and print
        print(siginfo_ptr.dereference())

class GetAddressInfo(gdb.Command):
    def __init__(self):
        super(GetAddressInfo, self).__init__("info_addr",gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        arg = arg.strip()
        if not arg:
            print("Usage: info_addr ADDRESS")
            return

        try:
            addr = int(gdb.parse_and_eval(arg))
        except Exception:
            print("Invalid address.")
            return
        
        try:
            output = gdb.execute('info proc mappings', to_string=True)
        except gdb.error:
            print("Not running or info proc mappings not supported.")
            return
        
        lines = output.splitlines()
        print(lines[3])
        for line in lines:
            info = line.strip().split()
            try:
                start_address = int(info[0], 16)
                end_address = int(info[1], 16)
                if(addr >= start_address and addr < end_address):
                    print(line)
                    return
            except:
                continue

        print("address not mapped")
        return
    
class PrintMem(gdb.Command):
    def __init__(self):
        super(PrintMem, self).__init__("print_mem",gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        virt_pages.print_mem()
        return
    
class LookupMem(gdb.Command):
    def __init__(self):
        super(LookupMem, self).__init__("lookup_mem",gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        arg = arg.strip()
        if not arg:
            print("Usage: lookup_mem ADDRESS")
            return

        try:
            addr = int(gdb.parse_and_eval(arg))
        except Exception:
            print("Invalid address.")
            return
        virt_pages.get_mem(addr)
        return






add_symbols_auto()
InfoBlocked()
InfoHandlers()
SafeHandleSig()
PrintSiginfo()
UContext()
GetAddressInfo()
PrintMem()
LookupMem()