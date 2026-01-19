const main_module = Process.mainModule;
const bin_base = main_module.base;
const binEnd = bin_base.add(main_module.size);
const main_offset = 0x17a8;
const main_addr = bin_base.add(main_offset);
send('[Load] Binary base: ' + bin_base);


send(`[+] Hooking main at ${main_addr}`);
Interceptor.attach(main_addr, {
    onEnter: function (args) {
        Stalker.follow(this.threadId, {
            events: {
                call: false,
                ret: false,
                exec: true,
                block: false,
                compile: false
            },
            onReceive: function (events) {
                for (const ev of Stalker.parse(events)) {
                    let addr = ev[1];
                    if (bin_base <= addr && addr <= binEnd) {
                        try {
                            const insn = Instruction.parse(addr);
                            send(`[Insn] ${addr} (${insn.size}): ${insn.mnemonic} ${insn.opStr}`);
                        } catch (err) {
                            send(`[Insn] ${addr} : <disasm failed>`);
                        }
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
        Stalker.flush();
        send(`[API] exit() called`);
        send(`      retaddr: ${this.returnAddress}`);

        const t0 = Date.now();
        while (Date.now() - t0 < 100) {}
    }
});
