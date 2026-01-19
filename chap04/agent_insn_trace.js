const main_module = Process.mainModule;
const bin_base = main_module.base;
const bin_end = bin_base.add(main_module.size);
send('[Load] Binary base: ' + bin_base);

var callsite_addr = null;

send('[+] Hooking localtime');
const libc = Process.getModuleByName('libc.so.6');
Interceptor.attach(libc.getExportByName('localtime'), {
    onLeave: function (retval) {
        send(`[API] localtime() called`);

        Stalker.follow(this.threadId, {
            transform: function (iterator) {
                let insn;
                while ((insn = iterator.next()) !== null) {
                    if (bin_base <= insn.address && insn.address <= bin_end) {
                        iterator.putCallout(function (context) {
                            const insn = Instruction.parse(context.pc);
                            send(`[Insn] ${insn.address} (${insn.size}): ${insn.mnemonic} ${insn.opStr}`);

                            if (insn.mnemonic == 'call') {
                                callsite_addr = insn.address;
                            }
                        },);
                    }
                    iterator.keep();
                }
            }
        });
    }
});

send('[+] Hooking exit');
Interceptor.attach(libc.getExportByName('exit'), {
    onEnter: function (args) {
        Stalker.flush();
        send(`[API] exit() called`);
        send(`      retaddr: ${this.returnAddress}`);
        send(`      callsite: ${callsite_addr}`);
        Thread.sleep(.1);
    }
});
