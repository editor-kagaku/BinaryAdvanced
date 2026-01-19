send('[+] Hooking localtime');
const libc = Process.getModuleByName('libc.so.6');
Interceptor.attach(libc.getExportByName('localtime'), {
    onLeave: function (retval) {
        if (retval.isNull()) {
            console.log('    localtime returned NULL');
            return;
        }

        const fake_tm = {
            tm_sec: 37,
            tm_min: 13,
            tm_hour: 3,
            tm_mday: 6,
            tm_mon: 3,
            tm_year: 2026,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0
        };

        const tm_ptr = retval;
        tm_ptr.add(0).writeS32(fake_tm.tm_sec);
        tm_ptr.add(4).writeS32(fake_tm.tm_min);
        tm_ptr.add(8).writeS32(fake_tm.tm_hour);
        tm_ptr.add(12).writeS32(fake_tm.tm_mday);
        tm_ptr.add(16).writeS32(fake_tm.tm_mon);
        tm_ptr.add(20).writeS32(fake_tm.tm_year);
        tm_ptr.add(24).writeS32(fake_tm.tm_wday);
        tm_ptr.add(28).writeS32(fake_tm.tm_yday);
        tm_ptr.add(32).writeS32(fake_tm.tm_isdst);

        console.log('    [*] Returned struct tm has been overwritten with fake time.');
    }
});

Interceptor.flush();
send('ready')
