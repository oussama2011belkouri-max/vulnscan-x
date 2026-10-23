#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    ██╗   ██╗██║   ██║██║      ███╗   ██║███████╗ ██████╗ █████╗ ███╗   ██║
    ██║   ██║██║   ██║██║      ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║   ██║██║   ██║██║      ██╔██╗ ██║█████╗  ██║     ███████║██╔██╗ ██║
    ╚██╗ ██╔╝██║   ██║██║      ██║╚██╗██║██╔══╝  ██║     ██╔══██║██║╚██╗██║
     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗╚██████╗██║  ██║██║ ╚████║
      ╚═══╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
         VULNSCAN-X v1.0 — Template-based Vuln Scanner (Fixed)
"""
import os, sys, re, json, time, socket, ssl, argparse, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ================= COLORS =================
class S:
    R="\033[1;91m"; G="\033[1;92m"; Y="\033[1;93m"; B="\033[1;94m"
    M="\033[1;95m"; C="\033[1;96m"; W="\033[0m"; DIM="\033[2m"; BOLD="\033[1m"

SEV_COLORS={"critical":S.R,"high":S.M,"medium":S.Y,"low":S.C,"info":S.DIM}
BANNER=f"""{S.R}
  ██╗   ██╗██║   ██║██║      ███╗   ██║███████╗ ██████╗ █████╗ ███╗   ██║
  ██║   ██║██║   ██║██║      ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║██║   ██║██║      ██╔██╗ ██║█████╗  ██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║      ██║╚██╗██║██╔══╝  ██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗╚██████╗██║  ██║██║ ╚████║
    ╚═══╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{S.W}{S.DIM}
    Template-based Vuln Scanner — fixed & optimized
    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{S.W}"""

# ================= HTTP HELPER =================
def http_req(url, method="GET", headers=None, data=None, timeout=10, follow=True):
    h={"User-Agent":"Mozilla/5.0 (compatible; VulnScanX/1.0)",**(headers or {})}
    req=urllib.request.Request(url,headers=h,data=data.encode() if isinstance(data,str) else data,method=method)
    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k): return None
    opener=urllib.request.build_opener(NoRedir) if not follow else urllib.request.build_opener()
    try:
        resp=opener.open(req,timeout=timeout)
        body=resp.read(200000).decode(errors="ignore")
        return {"status":resp.status,"headers":dict(resp.headers),"body":body,"url":resp.geturl(),"time":0}
    except urllib.error.HTTPError as e:
        body=e.read(200000).decode(errors="ignore")
        return {"status":e.code,"headers":dict(e.headers),"body":body,"url":url,"time":0}
    except Exception as e:
        return {"status":0,"headers":{},"body":"","url":url,"error":str(e),"time":0}

# ================= TEMPLATE ENGINE =================
class Template:
    def __init__(self,d):
        self.id=d.get("id","unknown"); self.sev=d.get("severity","info")
        self.tags=d.get("tags",[]); self.matchers=d.get("matchers",[])
        self.path=d.get("path",""); self.method=d.get("method","GET")
        self.headers=d.get("headers",{}); self.body=d.get("body")
        self.payloads=d.get("payloads",[]); self.extract=d.get("extract",[])
        self.desc=d.get("description",""); self.custom=d.get("custom","")
    def match(self,resp):
        results=[]
        for m in self.matchers:
            t=m["type"]
            if t=="status": results.append(resp["status"] in m.get("status",[]))
            elif t=="word":
                cond=m.get("condition","or")
                hits=[w.lower() in resp["body"].lower() for w in m.get("words",[])]
                results.append(all(hits) if cond=="and" else any(hits))
            elif t=="regex":
                cond=m.get("condition","or")
                hits=[bool(re.search(r, resp["body"], re.I)) for r in m.get("regex",[])]
                results.append(all(hits) if cond=="and" else any(hits))
            elif t=="header":
                hits=[k in resp["headers"] and bool(re.search(v,str(resp["headers"].get(k,"")),re.I))
                      for k,v in m.get("headers",{}).items()]
                results.append(all(hits) if m.get("condition","and")=="and" else any(hits))
            else: results.append(False)
        return all(results) if results else False

# ================= BUILT-IN TEMPLATES =================
def builtin_templates():
    T=[]
    def add(**kw): T.append(Template(kw))
    # --- Exposure / Sensitive files ---
    add(id="exposed-git",severity="high",tags=["exposure","git"],path="/.git/HEAD",
        description="Exposed .git repository",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["ref: refs/"]}])
    add(id="exposed-env",severity="critical",tags=["exposure","env"],path="/.env",
        description="Exposed .env file with secrets",
        matchers=[{"type":"status","status":[200]},{"type":"regex","regex":[r"(APP_KEY|DB_PASSWORD|AWS_SECRET|SECRET=.{8,})"]}])
    add(id="exposed-backup-sql",severity="critical",tags=["exposure","backup"],path="/backup.sql",
        description="Exposed SQL dump",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["CREATE TABLE","INSERT INTO"],"condition":"or"}])
    add(id="htaccess-exposed",severity="medium",tags=["exposure"],path="/.htaccess",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["RewriteEngine","<Files"],"condition":"or"}])
    add(id="exposed-docker",severity="high",tags=["exposure","docker"],path="/Dockerfile",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["FROM ","RUN "]}])
    add(id="composer-exposed",severity="low",tags=["exposure"],path="/composer.json",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["\"require\""]}])
    add(id="wp-config-bak",severity="critical",tags=["exposure","wordpress"],path="/wp-config.php.bak",
        matchers=[{"type":"status","status":[200]},{"type":"regex","regex":[r"DB_PASSWORD"]}])
    add(id="exposed-phpinfo",severity="high",tags=["exposure","php"],path="/info.php",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["phpinfo()","PHP Version"]}])
    add(id="server-status",severity="medium",tags=["apache"],path="/server-status",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["Apache Server Status"]}])
    add(id="actuator-exposed",severity="critical",tags=["java","spring"],path="/actuator/env",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["propertySources"]}])
    add(id="swagger-exposed",severity="medium",tags=["api"],path="/swagger-ui.html",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["swagger"]}])
    add(id="graphql-introspection",severity="medium",tags=["api","graphql"],method="POST",path="/graphql",
        body='{"query":"{ __schema { types { name } } }"}',
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["__schema"]}])
    # --- Misconfig / Headers ---
    add(id="cors-wildcard",severity="medium",tags=["misconfig","cors"],path="", custom="cors")
    add(id="security-headers",severity="low",tags=["misconfig","headers"],path="", custom="security_headers")
    # --- Injection (fuzzing templates) ---
    add(id="sqli-error-based",severity="critical",tags=["sqli","injection"],
        payloads=[["q",["'","1' OR '1'='1--","1 UNION SELECT NULL--"]]],
        matchers=[{"type":"regex","regex":[r"(sql syntax|mysql|unclosed quotation|ora-\d{5})"]}])
    add(id="xss-reflected",severity="high",tags=["xss"],
        payloads=[["q",['"><svg onload=alert(1)>','<script>alert(1)</script>']]],
        matchers=[{"type":"regex","regex":[r"<svg onload=alert\(1\)>|<script>alert\(1\)"]}])
    add(id="path-traversal",severity="high",tags=["lfi","traversal"],
        payloads=[["q",["../../../../etc/passwd","..%2f..%2f..%2fetc%2fpasswd"]]],
        matchers=[{"type":"regex","regex":[r"root:x:0:0:"]}])
    return T

# ================= CUSTOM CHECKS =================
def custom_cors_check(url):
    resp=http_req(url,headers={"Origin":"https://evil.com"})
    acao=resp["headers"].get("Access-Control-Allow-Origin","")
    if acao in ("https://evil.com","*","null") and resp["status"]==200:
        return f"Permissive CORS: ACAO={acao}"
    return None

def custom_security_headers(url):
    resp=http_req(url)
    if resp["status"] not in (200,301,302): return None
    missing=[h for h in ("Content-Security-Policy","X-Frame-Options",
             "X-Content-Type-Options","Strict-Transport-Security") if h not in resp["headers"]]
    if missing: return f"Missing security headers: {', '.join(missing)}"
    return None

# ================= SCANNER CORE =================
class VulnScanX:
    def __init__(self, targets, templates, workers=25, timeout=10, output=None):
        self.targets=targets; self.templates=templates
        self.workers=workers; self.timeout=timeout; self.output=output
        self.findings=[]; self.scanned=0; self.requests=0
    def log_finding(self,t,url,detail=""):
        f={"template":t.id,"severity":t.sev,"url":url,"tags":t.tags,"desc":t.desc,"detail":detail,"time":datetime.now().isoformat()}
        self.findings.append(f)
        c=SEV_COLORS.get(t.sev,S.W)
        print(f"  {c}[{t.sev.upper():8s}]{S.W} {S.BOLD}{t.id}{S.W} {S.DIM}— {url}{S.W}")
        if detail: print(f"     {S.DIM}↳ {detail[:150]}{S.W}")
    def run_template(self,t,base_url):
        urls=[]
        if t.payloads:
            parsed=urllib.parse.urlparse(base_url)
            q=urllib.parse.parse_qsl(parsed.query,keep_blank_values=True)
            if q:
                for pname,vals in t.payloads:
                    for v in vals:
                        nq=urllib.parse.urlencode([(k,v if k==pname else vv) for k,vv in q])
                        urls.append(urllib.parse.urlunparse(parsed._replace(query=nq)))
            else:
                for pname,vals in t.payloads:
                    for v in vals: urls.append(f"{base_url}?{pname}={urllib.parse.quote(v)}")
        elif t.path:
            urls.append(base_url.rstrip('/')+t.path)
        else:
            urls.append(base_url)
            
        for u in urls:
            self.requests+=1
            r=http_req(u,method=t.method,headers=t.headers,data=t.body,timeout=self.timeout)
            if r["status"]==0: continue
            if t.match(r):
                detail=""
                for ex in t.extract:
                    if ex.startswith("^note:"): detail=ex[7:]
                    else:
                        m=re.search(ex,r["body"])
                        if m: detail=m.group(0)[:150]
                self.log_finding(t,u,detail or r["body"][:100])
                
        # Custom checks handling
        if t.custom=="cors":
            d=custom_cors_check(base_url)
            if d: self.log_finding(t,base_url,d)
        if t.custom=="security_headers":
            d=custom_security_headers(base_url)
            if d: self.log_finding(t,base_url,d)

    def run(self):
        print(f"{S.B}┌──[ SCAN STARTED ]{S.W}")
        print(f"  {S.DIM}Targets: {len(self.targets)} | Templates: {len(self.templates)} | Workers: {self.workers}{S.W}\n")
        t0=time.time()
        jobs=[(t,u) for t in self.templates for u in self.targets]
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs={ex.submit(self.run_template,t,u):(t,u) for t,u in jobs}
            done=0
            for f in as_completed(futs):
                done+=1
                if done%50==0: print(f"  {S.DIM}[progress] {done}/{len(jobs)} checks...{S.W}")
                try: f.result()
                except Exception: pass
        elapsed=time.time()-t0
        print(f"\n{S.B}└──[ SCAN COMPLETE ]{S.W}")
        print(f"  {S.DIM}Time: {elapsed:.1f}s | Requests: {self.requests} | Findings: {len(self.findings)}{S.
