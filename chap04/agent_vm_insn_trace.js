const main_module = Process.mainModule;
const bin_base = main_module.base;
const bin_end = bin_base.add(main_module.size);
const main_offset = 0x17a8;
const main_addr = bin_base.add(main_offset);
const bytecode_access_offset = 0x13ba;
const bytecode_access_addr = main_module.base.add(bytecode_access_offset);
const bytecode_len = 20;
const decoder_offset = 0x13cb;
const decoder_addr = main_module.base.add(decoder_offset);
const dispatcher_offset = 0x1408;
const dispatcher_addr = main_module.base.add(dispatcher_offset);
var bytecode_addr;
var bytecode;
var is_bytecode_extracted = false;

Stalker.trustThreshold = -1;


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
                                const vpc = vpc_addr.readU8();
                                send(`[VPC] 0x${vpc.toString(16)}`);
                            } catch (e) {
                                send(`[VPC] failed to read: ${e.message}`);
                            }
                        });
                    }

                    if (insn_addr.equals(decoder_addr)) {
                        iterator.putCallout(function (context) {
                            try {
                                // const vmop = context.rax.toUInt32() & 0xff;
                                const vmop = context.rax.and(0xff);
                                send(`[VMOP] 0x${vmop.toString(16)}`);
                            } catch (e) {
                                send(`[VMOP] failed to read: ${e.message}`);
                            }
                        });
                    }   

                    if (insn_addr.equals(dispatcher_addr)) {
                        iterator.putCallout(function (context) {
                            try {
                                const vm_handler_addr = context.rax;
                                send(`[VM handler] 0x${vm_handler_addr.toString(16)}`);
                            } catch (e) {
                                send(`[VM handler] failed to read: ${e.message}`);
                            }
                        });
                    }

                    iterator.keep();

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
