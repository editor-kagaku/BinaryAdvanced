import angr
import claripy


class LocaltimeSymbolic(angr.SimProcedure):
    def run(self, time_ptr):
        tm_ptr = self.state.heap.allocate(64)

        self.state.memory.store(tm_ptr + 0, claripy.BVS('tm_sec', 32))
        self.state.memory.store(tm_ptr + 4, claripy.BVS('tm_min', 32))
        self.state.memory.store(tm_ptr + 8, claripy.BVS('tm_hour', 32))
        self.state.memory.store(tm_ptr + 12, claripy.BVS('tm_mday', 32))
        self.state.memory.store(tm_ptr + 16, claripy.BVS('tm_mon', 32))
        self.state.memory.store(tm_ptr + 20, claripy.BVS('tm_year', 32))
        for offset in range(24, 64, 4):
            self.state.memory.store(tm_ptr + offset, claripy.BVV(0, 32))

        self.state.globals['tm_sec'] = self.state.memory.load(tm_ptr + 0, 4, endness='Iend_LE')
        self.state.globals['tm_min'] = self.state.memory.load(tm_ptr + 4, 4, endness='Iend_LE')
        self.state.globals['tm_hour'] = self.state.memory.load(tm_ptr + 8, 4, endness='Iend_LE')
        self.state.globals['tm_mday'] = self.state.memory.load(tm_ptr + 12, 4, endness='Iend_LE')
        self.state.globals['tm_mon'] = self.state.memory.load(tm_ptr + 16, 4, endness='Iend_LE')
        self.state.globals['tm_year'] = self.state.memory.load(tm_ptr + 20, 4, endness='Iend_LE')

        return tm_ptr

def find_ret(cfg, target_func):
    for func_addr, func in cfg.kb.functions.items():
        if func.name == target_func:
            for block_addr in sorted(func.block_addrs_set):
                block = proj.factory.block(block_addr)

                for ins in block.capstone.insns:
                    if ins.mnemonic == 'ret':
                        return ins.address

proj = angr.Project('./sample1', auto_load_libs=False)

proj.hook_symbol('localtime', LocaltimeSymbolic())

state = proj.factory.full_init_state()
simgr = proj.factory.simgr(state)

bin_base = proj.loader.main_object.min_addr
cfg = proj.analyses.CFGFast()
exit_callsite_offset = 0x1250
exit_callsite_addr = bin_base + exit_callsite_offset
epilogue_addr = find_ret(cfg, 'main')
simgr.explore(find=epilogue_addr, avoid=exit_callsite_addr)

if simgr.found:
    found = simgr.found[0]
    tm_year = found.solver.eval(found.globals['tm_year'])
    tm_mon = found.solver.eval(found.globals['tm_mon'])
    tm_mday = found.solver.eval(found.globals['tm_mday'])
    tm_hour = found.solver.eval(found.globals['tm_hour'])
    tm_min = found.solver.eval(found.globals['tm_min'])
    tm_sec = found.solver.eval(found.globals['tm_sec'])
    print(f'[+] Condition met: {tm_year:04d}-{tm_mon:02d}-{tm_mday:02d} {tm_hour:02d}:{tm_min:02d}:{tm_sec:02d}')
else:
    print('[-] Could not find matching condition.')
