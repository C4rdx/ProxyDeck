#!/usr/bin/env python3
"""ProxyDeck: lightweight public-proxy catalogue, diagnostics, CLI and local UI."""
import concurrent.futures as cf
import http.server, json, os, platform, random, re, socket, subprocess, sys, threading, time, urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parent
if not os.environ.get("SSL_CERT_FILE"):
    for ca in (Path(sys.prefix).parent/"usr"/"ssl"/"cert.pem",Path(sys.prefix)/"etc"/"ssl"/"cert.pem"):
        if ca.is_file(): os.environ["SSL_CERT_FILE"]=str(ca); break
DB=ROOT/"proxies.json"; STATE=ROOT/"state.json"; UA="ProxyDeck/0.2"
SOURCES=[
("HProxy live","https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/live.txt","mixed"),
("Fusion HTTP","https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/http.txt","http"),
("Fusion SOCKS5","https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/socks5.txt","socks5"),
("Moleway all","https://raw.githubusercontent.com/Moleway/Free-Proxy-List/main/all.txt","mixed"),
("Proxy-free all","https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/all.txt","mixed"),
("iPlocate HTTP","https://raw.githubusercontent.com/iplocate/free-proxy-list/main/proxies/http.txt","http"),
("iPlocate SOCKS5","https://raw.githubusercontent.com/iplocate/free-proxy-list/main/proxies/socks5.txt","socks5"),
("Thordata all","https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/all.txt","mixed"),
("Databay HTTP","https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt","http"),
("Dahono HTTP","https://raw.githubusercontent.com/Dahono-com/free-proxy-list/main/proxies/http.txt","http")]
LOCK=threading.Lock()
SCAN={"running":False,"done":0,"total":0,"message":"Ready","kind":""}

def load_db():
    try: return json.loads(DB.read_text("utf-8"))
    except Exception: return []
def save_db(rows):
    tmp=DB.with_suffix(".tmp"); tmp.write_text(json.dumps(rows,ensure_ascii=False),"utf-8"); tmp.replace(DB)
def load_state():
    try: return json.loads(STATE.read_text("utf-8"))
    except Exception: return {}
def save_state(s): STATE.write_text(json.dumps(s,ensure_ascii=False,indent=2),"utf-8")
def request(url,proxy=None,timeout=8):
    handlers=[]
    if proxy:
        scheme,addr=proxy.split("://",1)
        if scheme in ("http","https"):
            handlers.append(urllib.request.ProxyHandler({"http":scheme+"://"+addr,"https":scheme+"://"+addr}))
        else: raise ValueError("SOCKS requires an external tunnel adapter")
    else: handlers.append(urllib.request.ProxyHandler({}))
    opener=urllib.request.build_opener(*handlers)
    req=urllib.request.Request(url,headers={"User-Agent":UA,"Cache-Control":"no-cache"})
    start=time.perf_counter()
    with opener.open(req,timeout=timeout) as r:
        data=r.read(2_000_000)
        return r.status,(time.perf_counter()-start)*1000,data
def parse_line(line,default):
    s=line.strip().strip('"').strip("'")
    if not s or s.startswith(("#","//","{","[")): return None
    if "://" not in s: s=default+"://"+s
    try:
        u=urlparse(s); scheme=u.scheme.lower(); host=u.hostname; port=u.port
        if scheme not in ("http","https","socks4","socks5") or not host or not port or not 1<=port<=65535: return None
        if not re.fullmatch(r"[A-Za-z0-9.:-]+",host): return None
        return {"id":scheme+"://"+host+":"+str(port),"address":host+":"+str(port),"protocol":scheme.upper(),"source":""}
    except Exception: return None
def fetch_source(src):
    name,url,kind=src
    try:
        _,_,data=request(url,timeout=18); rows=[]
        for line in data.decode("utf-8","replace").splitlines():
            p=parse_line(line,"http" if kind=="mixed" else kind)
            if p: p["source"]=name; rows.append(p)
        return rows,None
    except Exception as e: return [],name+": "+str(e)[:140]
def geo(ip):
    try:
        _,_,raw=request("https://ipwho.is/"+ip,timeout=5); j=json.loads(raw.decode("utf-8","replace"))
        if j.get("success",True): return j.get("country",""),j.get("country_code",""),j.get("city","")
    except Exception: pass
    return "","",""
def check(row):
    r=dict(row); proto=r["protocol"].lower()
    if proto not in ("http","https"):
        r.update(status="unsupported",latency_ms=None,tcp_ping_ms=None,youtube=False,gemini=False,general=False,
                 security="untrusted",stale=False,note="SOCKS endpoint retained for catalogue; activation is not implemented")
        return r
    # TCP handshake timing is a reachability signal, not ICMP ping.
    tcp_start=time.perf_counter()
    try:
        with socket.create_connection((urlparse(r["id"]).hostname,urlparse(r["id"]).port),timeout=4): pass
        tcp_ms=round((time.perf_counter()-tcp_start)*1000)
    except Exception: tcp_ms=None
    start=time.perf_counter()
    try:
        _,_,ipdata=request("https://api.ipify.org",r["id"],7)
        exit_ip=ipdata.decode("ascii","ignore").strip()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}",exit_ip): raise ValueError("invalid exit IP")
        latency=round((time.perf_counter()-start)*1000)
        tests={}
        for key,url in (("youtube","https://www.youtube.com/generate_204"),("gemini","https://gemini.google.com/"),("general","https://example.com/")):
            try:
                status,_,_=request(url,r["id"],5); tests[key]=200<=status<400 or status==204
            except Exception: tests[key]=False
        country,cc,city=geo(exit_ip)
        r.update(status="online",latency_ms=latency,tcp_ping_ms=tcp_ms,exit_ip=exit_ip,country=country,country_code=cc,city=city,
                 youtube=tests["youtube"],gemini=tests["gemini"],general=tests["general"],checked_at=int(time.time()),
                 security="untrusted",security_note="Public operator; no independent trust guarantee",stale=False)
    except Exception as e:
        r.update(status="offline",latency_ms=None,tcp_ping_ms=tcp_ms,youtube=False,gemini=False,general=False,
                 checked_at=int(time.time()),security="untrusted",error=str(e)[:100],stale=False)
    return r
def start_job(kind,total,message,fn):
    with LOCK:
        if SCAN["running"]: return False
        SCAN.update(running=True,done=0,total=total,message=message,kind=kind)
    def runner():
        try: fn()
        except Exception as e:
            with LOCK: SCAN["message"]=kind+" failed: "+str(e)[:180]
        finally:
            with LOCK: SCAN["running"]=False
    threading.Thread(target=runner,daemon=True).start()
    return True
def scan(limit=500):
    with LOCK:
        if SCAN["running"]: return SCAN["message"]
        SCAN.update(running=True,done=0,total=len(SOURCES),message="Downloading proxy sources…",kind="refresh")
    try:
        allrows=[]; errors=[]
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            fs=[ex.submit(fetch_source,s) for s in SOURCES]
            for f in cf.as_completed(fs):
                rows,err=f.result(); allrows.extend(rows)
                if err: errors.append(err)
                with LOCK: SCAN["done"]+=1
        dedup={}
        for p in allrows:
            if p["id"] in dedup:
                if p["source"] not in dedup[p["id"]]["source"]: dedup[p["id"]]["source"]+=", "+p["source"]
            else: dedup[p["id"]]=p
        candidates=list(dedup.values()); random.shuffle(candidates); candidates=candidates[:limit]
        if not candidates:
            msg="Refresh failed: no usable endpoints; saved catalogue preserved. "+("; ".join(errors[:3]))
            with LOCK: SCAN.update(total=0,done=0,message=msg)
            return msg
        with LOCK: SCAN.update(total=len(candidates),done=0,message="Testing "+str(len(candidates))+" endpoints…")
        results=[]
        with cf.ThreadPoolExecutor(max_workers=48) as ex:
            fs=[ex.submit(check,p) for p in candidates]
            for f in cf.as_completed(fs):
                results.append(f.result())
                with LOCK: SCAN["done"]+=1; SCAN["message"]="Testing endpoints: "+str(SCAN["done"])+" / "+str(SCAN["total"])
                if len(results)%25==0:
                    seen={x["id"] for x in results}
                    save_db(results+[dict(x,stale=True) for x in load_db() if x.get("id") not in seen])
        fresh={x["id"]:x for x in results}
        for old in load_db():
            if old.get("id") not in fresh: old["stale"]=True; results.append(old)
        results.sort(key=lambda x:(x.get("status")!="online",x.get("latency_ms") or 999999))
        save_db(results)
        msg="Refresh complete · "+str(sum(x.get("status")=="online" and not x.get("stale") for x in results))+" online · "+str(len(errors))+" source errors"
        with LOCK: SCAN["message"]=msg
        return msg
    except Exception as e:
        msg="Refresh failed: "+str(e)[:180]
        with LOCK: SCAN["message"]=msg
        return msg
    finally:
        with LOCK: SCAN["running"]=False
def test_all():
    rows=load_db()
    if not rows: 
        with LOCK: SCAN["message"]="No saved proxies to test"
        return
    with LOCK: SCAN.update(running=True,done=0,total=len(rows),message="Re-testing saved proxies…",kind="test-all")
    try:
        out=[]
        with cf.ThreadPoolExecutor(max_workers=40) as ex:
            fs=[ex.submit(check,x) for x in rows]
            for f in cf.as_completed(fs):
                out.append(f.result())
                with LOCK: SCAN["done"]+=1; SCAN["message"]="Re-testing saved proxies: "+str(SCAN["done"])+" / "+str(SCAN["total"])
                if len(out)%25==0:
                    ids={x["id"] for x in out}; save_db(out+[x for x in rows if x["id"] not in ids])
        out.sort(key=lambda x:(x.get("status")!="online",x.get("latency_ms") or 999999)); save_db(out)
        with LOCK: SCAN["message"]="Test complete · "+str(sum(x.get("status")=="online" for x in out))+" online"
    finally:
        with LOCK: SCAN["running"]=False
def test_one(proxy_id):
    rows=load_db(); idx=next((i for i,x in enumerate(rows) if x["id"]==proxy_id),None)
    if idx is None: return "Proxy not found"
    updated=check(rows[idx]); rows[idx]=updated; rows.sort(key=lambda x:(x.get("status")!="online",x.get("latency_ms") or 999999)); save_db(rows)
    return "Test complete: "+updated["status"]+" · "+str(updated.get("latency_ms") or "—")+" ms"
def connect(proxy_id):
    row=next((x for x in load_db() if x["id"]==proxy_id),None)
    if not row or row.get("status")!="online" or row.get("stale"): return "Select a freshly tested online proxy first."
    if row["protocol"]!="HTTP": return "Only HTTP proxy endpoints can be activated by this Windows setting."
    state=load_state()
    if platform.system()=="Windows":
        import winreg
        path=r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if "windows_original" not in state:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,path,0,winreg.KEY_READ) as k:
                old={}
                for n in ("ProxyEnable","ProxyServer","ProxyOverride"):
                    try: old[n]=winreg.QueryValueEx(k,n)[0]
                    except OSError: old[n]=0 if n=="ProxyEnable" else ""
            state["windows_original"]=old; save_state(state)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,path,0,winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k,"ProxyServer",0,winreg.REG_SZ,row["address"])
            winreg.SetValueEx(k,"ProxyOverride",0,winreg.REG_SZ,"<local>;localhost;127.*;10.*;192.168.*;*.ir")
            winreg.SetValueEx(k,"ProxyEnable",0,winreg.REG_DWORD,1)
        try:
            import ctypes
            ctypes.windll.Wininet.InternetSetOptionW(0,39,0,0); ctypes.windll.Wininet.InternetSetOptionW(0,37,0,0)
        except Exception: pass
    else: return "System proxy integration is not enabled on this Linux build."
    state["active"]=row["id"]; save_state(state); return "Connected: "+row["id"]
def disconnect():
    state=load_state()
    if platform.system()=="Windows" and "windows_original" in state:
        import winreg
        path=r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,path,0,winreg.KEY_SET_VALUE) as k:
            for n,v in state["windows_original"].items():
                winreg.SetValueEx(k,n,0,winreg.REG_DWORD if n=="ProxyEnable" else winreg.REG_SZ,v)
        try:
            import ctypes
            ctypes.windll.Wininet.InternetSetOptionW(0,39,0,0); ctypes.windll.Wininet.InternetSetOptionW(0,37,0,0)
        except Exception: pass
    state.pop("active",None); save_state(state); return "Previous proxy settings restored."
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def send(self,obj,code=200):
        b=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(b)))
        self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(b)
    def allowed(self):
        if self.headers.get("Host") not in ("127.0.0.1:8765","localhost:8765"): self.send({},403); return False
        return True
    def do_GET(self):
        if not self.allowed(): return
        if self.path=="/api/proxies": self.send({"rows":load_db(),"scan":SCAN,"state":load_state()})
        elif self.path=="/api/status": self.send({"scan":SCAN,"state":load_state()})
        elif self.path in ("/","/index.html"):
            b=(ROOT/"index.html").read_bytes(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
        else: self.send({},404)
    def do_POST(self):
        if not self.allowed(): return
        origin=self.headers.get("Origin")
        if origin and origin not in ("http://127.0.0.1:8765","http://localhost:8765"): self.send({},403); return
        try: data=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))) or b"{}")
        except Exception: data={}
        if self.path=="/api/scan":
            if SCAN["running"]: ok=False
            else:
                threading.Thread(target=scan,daemon=True).start(); ok=True
            self.send({"ok":ok,"message":"Refresh started" if ok else "A task is already running"})
        elif self.path=="/api/test-all":
            ok=start_job("test-all",len(load_db()),"Testing saved endpoints…",test_all)
            self.send({"ok":ok,"message":"Test started" if ok else "A task is already running"})
        elif self.path=="/api/test":
            pid=str(data.get("id",""))
            ok=start_job("test-one",1,"Testing selected endpoint…",lambda:one_job(pid))
            self.send({"ok":ok,"message":"Test started" if ok else "A task is already running"})
        elif self.path=="/api/connect": self.send({"message":connect(str(data.get("id","")))})
        elif self.path=="/api/disconnect": self.send({"message":disconnect()})
        else: self.send({},404)
def scan_job(): scan()
def one_job(pid):
    msg=test_one(pid)
    with LOCK: SCAN.update(done=1,message=msg)
def serve():
    server=http.server.ThreadingHTTPServer(("127.0.0.1",8765),Handler)
    print("ProxyDeck UI: http://127.0.0.1:8765")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
def clear_screen(): os.system("cls" if os.name=="nt" else "clear")
def connected_label():
    a=load_state().get("active")
    return a or "Not connected"
def print_header():
    print("="*72); print("ProxyDeck  |  Public proxy diagnostics")
    print("CONNECTED: "+connected_label()); print("="*72)
def tags(r):
    return " ".join(t for k,t in (("general","web-general"),("youtube","web-youtube"),("gemini","web-gemini")) if r.get(k))
def ping_sort_key(x):
    value=x.get("tcp_ping_ms")
    if value is None: value=x.get("latency_ms")
    return (value is None,value if value is not None else 999999)
def show_rows(rows):
    rows=sorted(rows,key=ping_sort_key)
    print(f"{'#':>3} {'ENDPOINT':<23} {'TCP':>6} {'WEB':>7} {'TAGS':<23} {'COUNTRY':<16} STATUS")
    print("-"*100)
    for i,r in enumerate(rows,1):
        tcp=str(r.get("tcp_ping_ms") if r.get("tcp_ping_ms") is not None else "-")
        web=str(r.get("latency_ms") if r.get("latency_ms") is not None else "-")
        print(f"{i:>3} {r.get('address',''):<23} {tcp:>6} {web:>7} {tags(r):<23} {r.get('country','')[:16]:<16} {r.get('status','?')}")
def menu():
    while True:
        clear_screen(); print_header()
        print("1. Refresh sources (discover new endpoints)")
        print("2. Test / ping all saved proxies")
        print("3. Show saved proxies (sorted by TCP ping)")
        print("4. Connect to an online HTTP proxy")
        print("5. Disconnect and restore previous settings")
        print("6. Open local dashboard")
        print("7. Exit")
        choice=input("\nProxyDeck > ").strip()
        if choice=="1":
            print("\nRefreshing sources…"); print(scan(500)); input("\nEnter to continue…")
        elif choice=="2":
            print("\nTesting all saved proxies…"); test_all(); print(SCAN["message"]); input("\nEnter to continue…")
        elif choice=="3":
            clear_screen(); print_header(); show_rows(load_db()); input("\nEnter to return…")
        elif choice=="4":
            rows=sorted([x for x in load_db() if x.get("status")=="online" and x.get("protocol")=="HTTP" and not x.get("stale")],
                        key=ping_sort_key)
            clear_screen(); print_header(); show_rows(rows)
            if rows:
                try:
                    n=int(input("\nSelect proxy number (0 to cancel): "))
                    if n:
                        msg=connect(rows[n-1]["id"]); clear_screen(); print_header()
                        print("\n"+msg+"\n")
                        print("ACTIVE PROXY: "+connected_label())
                except (ValueError,IndexError): print("Invalid selection.")
            input("\nEnter to return…")
        elif choice=="5": print("\n"+disconnect()); input("\nEnter to continue…")
        elif choice=="6":
            import webbrowser
            webbrowser.open("http://127.0.0.1:8765")
            try: serve()
            except OSError as e: print(e); input("\nEnter…")
        elif choice=="7": break
if __name__=="__main__":
    if "--scan" in sys.argv: print(scan(int(sys.argv[sys.argv.index("--scan")+1]) if len(sys.argv)>2 else 500))
    elif "--ui" in sys.argv: serve()
    else: menu()
