const main_module = Process.mainModule;
const bin_base = main_module.base;
const bin_end = bin_base.add(main_module.size);
const main_offset = 0x17a8;
const main_addr = bin_base.add(main_offset);
send('[Load] Binary base: ' + bin_base);


function get_full_size_reg(reg) {
    let m = /^(r1[0-5]|r[8-9])(d|w|b)$/.exec(reg);
    if (m) return m[1];

    const map = {
        al: 'rax', ah: 'rax', ax: 'rax', eax: 'rax', rax: 'rax',
        bl: 'rbx', bh: 'rbx', bx: 'rbx', ebx: 'rbx', rbx: 'rbx',
        cl: 'rcx', ch: 'rcx', cx: 'rcx', ecx: 'rcx', rcx: 'rcx',
        dl: 'rdx', dh: 'rdx', dx: 'rdx', edx: 'rdx', rdx: 'rdx',
        sil: 'rsi', si: 'rsi', esi: 'rsi', rsi: 'rsi',
        dil: 'rdi', di: 'rdi', edi: 'rdi', rdi: 'rdi',
        bpl: 'rbp', bp: 'rbp', ebp: 'rbp', rbp: 'rbp',
        spl: 'rsp', sp: 'rsp', esp: 'rsp', rsp: 'rsp',
        eip: 'rip', rip: 'rip',
    };

    return map[reg] ?? reg;
}

function ptr_mul(addr, scale) {
    const v1 = BigInt(addr.toString());
    const v2 = BigInt(scale);
    return ptr('0x' + (v1 * v2).toString(16));
}

function calc_addr(op, insn, context) {
    const base_reg = op.value.base;
    const index_reg = op.value.index;
    const scale = op.value.scale || 1;
    const disp = op.value.disp || 0;

    let addr = ptr(0);

    if (base_reg) {
        if (base_reg === 'rip') {
            addr = insn.address.add(insn.size);
        } else {
            const base = context[get_full_size_reg(base_reg)];
            addr = addr.add(base);
        }
    }

    if (index_reg) {
        const index = context[get_full_size_reg(index_reg)];
        addr = addr.add(ptr_mul(index, scale));
    }

    addr = addr.add(disp);

    return addr;
}

function trace_regs(context, insn, rw) {
    let regs;
    if (rw === 'r') {
        regs = insn.regsAccessed.read;
    } else if (rw === 'w') {
        regs = insn.regsAccessed.written;
    }

    if (regs.length > 0) {
        if (rw === 'r')
            send('       Read regs: ');
        else if (rw === 'w')
            send('       Written regs: ');
        for (const reg of regs) {
            send(`           ${reg}: ${context[get_full_size_reg(reg)]}`);
        }
    }
}

function read_mem_value(addr, size) {
    switch (size) {
        case 1: return '0x' + addr.readU8().toString(16);
        case 2: return '0x' + addr.readU16().toString(16);
        case 4: return '0x' + addr.readU32().toString(16);
        case 8: return '0x' + addr.readU64().toString(16);
        default: {
            const buf = addr.readByteArray(size);
            return hexdump(buf, { offset: 0, length: size, header: false, ansi: false }).trim();
        }
    }
}

function trace_mems(context, insn, rw) {
    const mems = [];
    for (let index = 0; index < insn.operands.length; index++) {
        const op = insn.operands[index];
        if (op.type === 'mem' && op.access.includes(rw)) mems.push({ index, op });
    }

    if (mems.length > 0) {
        if (rw === 'r')
            send('       Read mems: ');
        else if (rw === 'w')
            send('       Written mems: ');
        for (const mem of mems) {
            const addr = calc_addr(mem.op, insn, context);
            const size = mem.op.size
            const value = read_mem_value(addr, size);
            send(`           op${mem.index + 1}: ${addr} (${size}) ${value}`);
        }
    }
}


send(`[+] Hooking main at ${main_addr}`);
Interceptor.attach(main_addr, {
    onEnter: function (args) {
        Stalker.follow(this.threadId, {
            transform: function (iterator) {
                let insn;
                while ((insn = iterator.next()) !== null) {
                    const insn_addr = insn.address;
                    if (bin_base <= insn.address && insn.address <= bin_end) {
                        iterator.putCallout(function (context) {
                            const insn = Instruction.parse(insn_addr);
                            send(`[Insn] ${insn.address} (${insn.size}): ${insn.mnemonic} ${insn.opStr}`);
                            trace_regs(context, insn, 'r');
                            trace_mems(context, insn, 'r');
                        },);
                    }

                    iterator.keep();

                    if (bin_base <= insn.address && insn.address <= bin_end) {
                        iterator.putCallout(function (context) {
                            const insn = Instruction.parse(insn_addr);
                            trace_regs(context, insn, 'w');
                            trace_mems(context, insn, 'w');
                        },);
                    }
                }
            }
        });
    }
});


send('[+] Hooking exit');
const libc = Process.getModuleByName('libc.so.6');
Interceptor.attach(libc.getExportByName('exit'), {
    onEnter: function (args) {
        Stalker.flush();
        send(`[API] exit() called`);
        send(`      retaddr: ${this.returnAddress}`);
        Thread.sleep(.1);
    }
});
