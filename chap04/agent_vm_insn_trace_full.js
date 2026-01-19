const main_module = Process.mainModule;
const bin_base = main_module.base;
const bin_end = bin_base.add(main_module.size);
const main_offset = 0x17a8;
const main_addr = bin_base.add(main_offset);
const bytecode_access_offset = 0x13ba;
const bytecode_access_addr = main_module.base.add(bytecode_access_offset);
const bytecode_len = 0x40;
const decoder_offset = 0x13cb;
const decoder_addr = main_module.base.add(decoder_offset);
const decoder2_offset = 0x1657;
const decoder2_addr = main_module.base.add(decoder2_offset);
const dispatcher_offset = 0x1408;
const dispatcher_addr = main_module.base.add(dispatcher_offset);

const VM_TIME_epilogue_offset = 0x16b0;
const VM_TIME_getop1_offset = 0x16a9;

const VM_LOCALTIME_epilogue_offset = 0x1712;
const VM_LOCALTIME_getop1_offset = 0x16fe;
const VM_LOCALTIME_getop2_offset = 0x16be;

const VM_LOAD_epilogue_offset = 0x1632;
const VM_LOAD_getop1_offset = 0x162c;
const VM_LOAD_getop2_offset = 0x1624;

const VM_CMP_epilogue_offset = 0x14c2;
const VM_CMP_getop1_offset = 0x14af;
const VM_CMP_getop2_offset = 0x14b3;
const VM_CMP_getop3_offset = 0x14b9;

const VM_JZ_epilogue_offset = 0x14f4;
const VM_JZ_getop1_offset = 0x14ed;
const VM_JZ_getop2_offset = 0x14e7;

const VM_EXIT_epilogue_offset = 0x1755;
const VM_EXIT_getop1_offset = 0x1750;

const VM_TIME_epilogue_addr = bin_base.add(VM_TIME_epilogue_offset);
const VM_TIME_getop1_addr = bin_base.add(VM_TIME_getop1_offset);

const VM_LOCALTIME_epilogue_addr = bin_base.add(VM_LOCALTIME_epilogue_offset);
const VM_LOCALTIME_getop1_addr = bin_base.add(VM_LOCALTIME_getop1_offset);
const VM_LOCALTIME_getop2_addr = bin_base.add(VM_LOCALTIME_getop2_offset);

const VM_LOAD_epilogue_addr = bin_base.add(VM_LOAD_epilogue_offset);
const VM_LOAD_getop1_addr = bin_base.add(VM_LOAD_getop1_offset);
const VM_LOAD_getop2_addr = bin_base.add(VM_LOAD_getop2_offset);

const VM_CMP_epilogue_addr = bin_base.add(VM_CMP_epilogue_offset);
const VM_CMP_getop1_addr = bin_base.add(VM_CMP_getop1_offset);
const VM_CMP_getop2_addr = bin_base.add(VM_CMP_getop2_offset);
const VM_CMP_getop3_addr = bin_base.add(VM_CMP_getop3_offset);

const VM_JZ_epilogue_addr = bin_base.add(VM_JZ_epilogue_offset);
const VM_JZ_getop1_addr = bin_base.add(VM_JZ_getop1_offset);
const VM_JZ_getop2_addr = bin_base.add(VM_JZ_getop2_offset);

const VM_EXIT_epilogue_addr = bin_base.add(VM_EXIT_epilogue_offset);
const VM_EXIT_getop1_addr = bin_base.add(VM_EXIT_getop1_offset);

var VM_TIME_op1_addr;
var VM_TIME_op1_val;

var VM_LOCALTIME_op1_addr;
var VM_LOCALTIME_op2_addr;
var VM_LOCALTIME_op2_val;

var VM_LOAD_op1;
var VM_LOAD_op2_addr;
var VM_LOAD_op2_val;

var VM_CMP_op1;
var VM_CMP_op2;
var VM_CMP_op3;

var VM_JZ_op1;
var VM_JZ_op2;

var VM_EXIT_op1;


var vpc;
var vmop;
var vmop2;
var bytecode_addr;
var bytecode;
var is_bytecode_extracted = false;


Stalker.trustThreshold = -1;


function insert_callbacks(insn_addr, iterator, callbacks) {
    for (const cb of callbacks) {
        if (insn_addr.equals(cb['addr'])) {
            iterator.putCallout(cb['func']);
            break;
        }
    }
}

function lookup_vm_mnemonic(vmop) {
    let vm_mnemonic;

    switch(vmop) {
        case 0x4:
            vm_mnemonic = 'VM_CMP_EQ';
            break;
        case 0x5:
            vm_mnemonic = 'VM_JZ';
            break;
        case 0xb:
            vm_mnemonic = 'VM_LOAD';
            break;
        case 0xc:
            switch(vmop2) {
                case 0x10:
                    vm_mnemonic = 'VM_TIME';
                    break;
                case 0x11:
                    vm_mnemonic = 'VM_LOCALTIME';
                    break;
                default:
                    vm_mnemonic = 'VM_CALL_UNKNOWN';
                    break;
            }
            break;
        case 0xff:
            vm_mnemonic = 'VM_EXIT';
            break;
        default:
            vm_mnemonic = 'Unknown';
    }

    return vm_mnemonic;
}

function callback_VM_TIME_getop1_enter(context) {
    VM_TIME_op1_val = context.rax;
    VM_TIME_op1_addr = context.rbp.sub(0xd0);
}

function callback_VM_TIME_epilogue_enter(context) {
    send(`vpc: 0x${vpc.toString(16)}, vmop: ${lookup_vm_mnemonic(vmop)}, time_t addr: 0x${VM_TIME_op1_addr.toString(16)}, time_t val: ${VM_TIME_op1_val.toString(10)}`);
}

function callback_VM_LOCALTIME_getop1_leave(context) {
    VM_LOCALTIME_op1_addr = context.rcx;
}

function callback_VM_LOCALTIME_getop2_leave(context) {
    VM_LOCALTIME_op2_addr = context.rbp.sub(0xd0);
    VM_LOCALTIME_op2_val = context.rax;
}

function dump_memory(addr, size) {
    let mem = addr.readByteArray(size);
    send(`mem[0x${addr.toString(16)}-0x${addr.add(size).toString(16)}]:\n${hexdump(mem, { ansi: true })}`);
}

function callback_VM_LOCALTIME_epilogue_enter(context) {
    send(`vpc: 0x${vpc.toString(16)}, vmop: ${lookup_vm_mnemonic(vmop)}, tm addr: 0x${VM_LOCALTIME_op1_addr.toString(16)}, clock addr: 0x${VM_LOCALTIME_op2_addr.toString(16)}, clock val: ${VM_LOCALTIME_op2_val.toString(10)}`);
    dump_memory(VM_LOCALTIME_op1_addr, 36);
}

function callback_VM_LOAD_getop1_enter(context) {
    VM_LOAD_op1 = context.rbp.sub(0x146);
}

function callback_VM_LOAD_getop2_enter(context) {
    VM_LOAD_op2_addr = context.rbp.add(context.rax).sub(0x110);
}

function callback_VM_LOAD_getop2_leave(context) {
    VM_LOAD_op2_val = context.rax.and(0xff);
}

function callback_VM_LOAD_epilogue_enter(context) {
    send(`vpc: 0x${vpc.toString(16)}, vmop: ${lookup_vm_mnemonic(vmop)}, dest: 0x${VM_LOAD_op1.toString(16)}, src addr: 0x${VM_LOAD_op2_addr.toString(16)}, src val: ${VM_LOAD_op2_val.toString(10)}`);
}

function callback_VM_CMP_getop1_enter(context) {
    const addr = context.rbp.sub(0x146);
    VM_CMP_op1 = addr.readU8();
}

function callback_VM_CMP_getop2_leave(context) {
    VM_CMP_op2 = context.rax.and(0xff);
}

function callback_VM_CMP_getop3_leave(context) {
    VM_CMP_op3 = context.rax.and(0xff);
}

function callback_VM_CMP_epilogue_enter(context) {
    send(`vpc: 0x${vpc.toString(16)}, vmop: ${lookup_vm_mnemonic(vmop)}, val1: ${VM_CMP_op1}, val2: ${VM_CMP_op2.toString(10)}, result flag: ${VM_CMP_op3.toString(10)}`);
}

function callback_VM_JZ_getop1_enter(context) {
    const addr = context.rbp.sub(0x145);
    VM_JZ_op1 = addr.readU8();
}

function callback_VM_JZ_getop2_leave(context) {
    const addr = context.rbp.sub(0x141);
    VM_JZ_op2 = addr.readU8();
}

function callback_VM_JZ_epilogue_enter(context) {
    send(`vpc: 0x${vpc.toString(16)}, vmop: ${lookup_vm_mnemonic(vmop)}, flag: ${VM_JZ_op1}, dest: 0x${VM_JZ_op2.toString(16)}`);
}

function callback_VM_EXIT_getop1_leave(context) {
    VM_EXIT_op1 = context.rdi.and(0xff);
}

function callback_VM_EXIT_epilogue_enter(context) {
    send(`vpc: 0x${vpc.toString(16)}, vmop: ${lookup_vm_mnemonic(vmop)}, status: ${VM_EXIT_op1.toString(10)}`);
}

send('[Load] Binary base: ' + bin_base);

send(`[+] Hooking main at ${main_addr}`);
Interceptor.attach(main_addr, {
    onEnter: function (args) {
        Stalker.follow(this.threadId, {
            transform: function (iterator) {
                let insn;

                while ((insn = iterator.next()) !== null) {
                    const insn_addr = insn.address;
                    const insn_text = insn.toString();

                    if (insn.mnemonic.startsWith('mov') && insn_text.includes(', byte ptr [rbp - 0x147]')) {
                        iterator.putCallout(function (context) {
                            try {
                                const vpc_addr = context.rbp.sub(0x147);
                                vpc = vpc_addr.readU8();
                                // send(`[VPC] 0x${vpc.toString(16)}`);
                            } catch (e) {
                                send(`[VPC] failed to read: ${e.message}`);
                            }
                        });
                    }

                    if (insn_addr.equals(decoder_addr)) {
                        iterator.putCallout(function (context) {
                            try {
                                vmop = context.rax.and(0xff).toUInt32();
                                // const vmop = context.rax.and(0xff);
                                // send(`[VMOP] 0x${vmop.toString(16)}`);
                            } catch (e) {
                                send(`[VMOP] failed to read: ${e.message}`);
                            }
                        });
                    }   

                    if (insn_addr.equals(decoder2_addr)) {
                        iterator.putCallout(function (context) {
                            try {
                                vmop2 = context.rax.and(0xff).toUInt32();
                            } catch (e) {
                                send(`[VMOP2] failed to read: ${e.message}`);
                            }
                        });
                    }

                    const enter_callbacks = [
                        {'addr': VM_TIME_getop1_addr,        'func': callback_VM_TIME_getop1_enter},
                        {'addr': VM_TIME_epilogue_addr,      'func': callback_VM_TIME_epilogue_enter},
                        {'addr': VM_LOCALTIME_epilogue_addr, 'func': callback_VM_LOCALTIME_epilogue_enter},
                        {'addr': VM_LOAD_getop1_addr,        'func': callback_VM_LOAD_getop1_enter},
                        {'addr': VM_LOAD_getop2_addr,        'func': callback_VM_LOAD_getop2_enter},
                        {'addr': VM_LOAD_epilogue_addr,      'func': callback_VM_LOAD_epilogue_enter},
                        {'addr': VM_CMP_getop1_addr,         'func': callback_VM_CMP_getop1_enter},
                        {'addr': VM_CMP_epilogue_addr,       'func': callback_VM_CMP_epilogue_enter},
                        {'addr': VM_EXIT_epilogue_addr,      'func': callback_VM_EXIT_epilogue_enter},
                        {'addr': VM_JZ_getop1_addr,          'func': callback_VM_JZ_getop1_enter},
                        {'addr': VM_JZ_epilogue_addr,        'func': callback_VM_JZ_epilogue_enter}
                    ];
                    insert_callbacks(insn_addr, iterator, enter_callbacks);

                    iterator.keep();

                    const leave_callbacks = [
                        {'addr': VM_LOCALTIME_getop1_addr, 'func': callback_VM_LOCALTIME_getop1_leave},
                        {'addr': VM_LOCALTIME_getop2_addr, 'func': callback_VM_LOCALTIME_getop2_leave},
                        {'addr': VM_LOAD_getop2_addr,      'func': callback_VM_LOAD_getop2_leave},
                        {'addr': VM_CMP_getop2_addr,       'func': callback_VM_CMP_getop2_leave},
                        {'addr': VM_CMP_getop3_addr,       'func': callback_VM_CMP_getop3_leave},
                        {'addr': VM_JZ_getop2_addr,        'func': callback_VM_JZ_getop2_leave},
                        {'addr': VM_EXIT_getop1_addr,      'func': callback_VM_EXIT_getop1_leave}
                    ];
                    insert_callbacks(insn_addr, iterator, leave_callbacks);

                    if (!is_bytecode_extracted && insn_addr.equals(bytecode_access_addr) && insn.mnemonic.startsWith('lea')) {
                        iterator.putCallout(function (context) {
                            try {
                                bytecode_addr = context.rdx;
                                bytecode = bytecode_addr.readByteArray(bytecode_len);
                            } catch (e) {
                                send(`[Bytecode] failed to read: ${e.message}`);
                            }
                        });
                        is_bytecode_extracted = true;
                    }
                }
            }
        });
    },

    onLeave: function (retval) {
        Stalker.flush();
    }
});

send('[+] Hooking exit');
const libc = Process.getModuleByName('libc.so.6');
Interceptor.attach(libc.getExportByName('exit'), {
    onEnter: function (args) {
        send(`[Bytecode] addr: ${bytecode_addr}\n${hexdump(bytecode, { ansi: true })}`);
        Stalker.flush();
        Thread.sleep(.1);
    }
});
