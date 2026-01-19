send('[+] Hooking localtime');
const libc = Process.getModuleByName('libc.so.6');
Interceptor.attach(libc.getExportByName('localtime'), {
    onEnter: function (args) {
        const time_ptr = args[0];
        const timestamp = time_ptr.readU64();
        send(`[API] localtime`);
        send(`    time_t: ${timestamp} (${new Date(Number(timestamp) * 1000).toUTCString()})`);
    },
    onLeave: function (retval) {
        if (retval.isNull()) {
            send('    Returned NULL');
            return;
        }

        const tm_ptr = retval;
        const tm_sec   = tm_ptr.readS32();
        const tm_min   = tm_ptr.add(4).readS32();
        const tm_hour  = tm_ptr.add(8).readS32();
        const tm_mday  = tm_ptr.add(12).readS32();
        const tm_mon   = tm_ptr.add(16).readS32();
        const tm_year  = tm_ptr.add(20).readS32();
        const tm_wday  = tm_ptr.add(24).readS32();
        const tm_yday  = tm_ptr.add(28).readS32();
        const tm_isdst = tm_ptr.add(32).readS32();

        send(`    struct tm: ${tm_year + 1900}-${tm_mon + 1}-${tm_mday} ${tm_hour}:${tm_min}:${tm_sec}`);
        send(`        wday=${tm_wday}, yday=${tm_yday}, isdst=${tm_isdst}`);
    }
});

send('[+] Hooking exit');
Interceptor.attach(libc.getExportByName('exit'), {
    onEnter: function (args) {
        const exit_status = args[0];
        send(`[API] exit`);
        send(`    status: ${exit_status}`);
        Thread.sleep(.1);
    }
});
