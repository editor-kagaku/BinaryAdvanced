import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f'[JS] {message['payload']}')

agent_script = sys.argv[1]
target_binary = sys.argv[2]

pid = frida.spawn(target_binary)
session = frida.attach(pid)

with open(agent_script, 'r') as f:
    script = session.create_script(f.read())
script.on('message', on_message)
script.load()

print('[*] Script loaded. Press Ctrl+C to quit.')
frida.resume(pid)

try:
    sys.stdin.read()
except KeyboardInterrupt:
    print('[*] Detaching...')
    session.detach()
