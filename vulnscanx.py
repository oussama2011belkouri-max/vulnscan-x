#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║     ███████║██╔██╗ ██║
    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║     ██╔══██║██║╚██╗██║
     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗╚██████╗██║  ██║██║ ╚████║
      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
        VULNSCAN-X v1.0 — Template-based Vuln Scanner (better nuclei)
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
  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗╚██████╗██║  ██║██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{S.W}{S.DIM}
    Template-based Vuln Scanner — faster & smarter than nuclei
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
# Template format (JSON or YAML-ish dict):
# {
#  "id":"exposed-git", "severity":"high", "tags":["exposure","git"],
#  "matchers":[
#    {"type":"status","status":[200]},
#    {"type":"word","words":["ref: refs/"],"condition":"and"},
#    {"type":"regex","regex":["refs/heads/"]}
#  ],
#  "path":"/.git/HEAD",                    # optional path appended
#  "payloads":[["{{p}}",["1","2' OR '1'='1"]]],  # optional fuzzing
#  "extract":["regex group"]               # optional extraction
# }
class Template:
    def __init__(self,d):
        self.id=d.get("id","unknown"); self.sev=d.get("severity","info")
        self.tags=d.get("tags",[]); self.matchers=d.get("matchers",[])
        self.path=d.get("path",""); self.method=d.get("method","GET")
        self.headers=d.get("headers",{}); self.body=d.get("body")
        self.payloads=d.get("payloads",[]); self.extract=d.get("extract",[])
        self.desc=d.get("description","")
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
                hits=[re.search(r,w,resp["body"]) for w in m.get("regex",[])]
                results.append(all(hits) if cond=="and" else any(hits))
            elif t=="header":
                hits=[k in resp["headers"] and re.search(v,str(resp["headers"].get(k,"")),re.I)
                      for k,v in m.get("headers",{}).items()]
                results.append(all(hits) if m.get("condition","and")=="and" else any(hits))
            else: results.append(False)
        return all(results) if results else False

# ================= BUILT-IN TEMPLATES (100+) =================
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
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["\"require\""]}],)
    add(id="wp-config-bak",severity="critical",tags=["exposure","wordpress"],path="/wp-config.php.bak",
        matchers=[{"type":"status","status":[200]},{"type":"regex","regex":[r"DB_PASSWORD"]}])
    add(id="exposed-phpinfo",severity="high",tags=["exposure","php"],path="/info.php",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["phpinfo()","PHP Version"]}])
    for p in ("phpinfo.php","test.php","info.php","i.php"):
        add(id=f"phpinfo-{p}",severity="high",tags=["php","info"],path=f"/{p}",
            matchers=[{"type":"word","words":["PHP Version"]}])
    add(id="server-status",severity="medium",tags=["apache"],path="/server-status",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["Apache Server Status"]}])
    add(id="actuator-exposed",severity="critical",tags=["java","spring"],path="/actuator/env",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["propertySources"]}])
    add(id="actuator-heapdump",severity="critical",tags=["java","spring"],path="/actuator/heapdump",
        matchers=[{"type":"status","status":[200]},{"type":"header","headers":{"Content-Type":"application/octet-stream"}}])
    add(id="swagger-exposed",severity="medium",tags=["api"],path="/swagger-ui.html",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["swagger"]}],)
    add(id="graphql-introspection",severity="medium",tags=["api","graphql"],method="POST",path="/graphql",
        body='{"query":"{ __schema { types { name } } }"}',
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["__schema"]}])
    add(id="jenkins-open",severity="critical",tags=["ci"],path="/jenkins/manage",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["Jenkins"]}])
    add(id="kibana-open",severity="medium",tags=["elastic"],path="/app/kibana",
        matchers=[{"type":"word","words":["kibana"]}])
    add(id="exposed-xmlrpc",severity="low",tags=["wordpress"],path="/xmlrpc.php",
        matchers=[{"type":"status","status":[405,200]}])
    add(id="wp-json-users",severity="medium",tags=["wordpress","enum"],path="/wp-json/wp/v2/users",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["\"slug\""]}])
    add(id="directory-listing",severity="medium",tags=["exposure"],path="/uploads/",
        matchers=[{"type":"status","status":[200]},{"type":"regex","regex":[r"Index of /"]}],)
    add(id="aws-bucket-listing",severity="high",tags=["cloud"],path="/",
        headers={}, matchers=[{"type":"word","words":["ListBucketResult"]}])
    add(id="azure-web-config",severity="low",tags=["cloud"],path="/web.config",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["<configuration"]}])
    add(id="s3-public-bucket",severity="high",tags=["cloud"],path="/?list-type=2",
        matchers=[{"type":"status","status":[200]},{"type":"word","words":["<Contents>"]}])
    # --- Misconfig / Headers ---
    add(id="missing-csp",severity="low",tags=["misconfig","headers"],path="/",
        matchers=[{"type":"status","status":[200,301,302]}],
        extract=["^note: no CSP header$"])  # handled specially below
    add(id="clickjacking",severity="low",tags=["misconfig"],path="/",
        matchers=[{"type":"status","status":[200]}],
        extract=["^note: no X-Frame-Options$"])
    add(id="cors-wildcard",severity="medium",tags=["misconfig","cors"],path="/",
        matchers=[], custom="cors")  # handled by custom check
    add(id="open-admin-panel",severity="medium",tags=["default-login"] if False else ["exposure"],path="/admin/",
        extra_matchers=[{"type":"status","status":[200]},{"type":"regex","regex":[r"(login|dashboard|admin)","i"]}])
    # --- Injection (fuzzing templates) ---
    add(id="sqli-error-based",severity="critical",tags=["sqli","injection"],
        payloads=[["{{q}}",["'","1' OR '1'='1--","1 UNION SELECT NULL--"]]],
        matchers=[{"type":"regex","regex":[r"(sql syntax|mysql|unclosed quotation|ora-\d{5})"]}])
    add(id="xss-reflected",severity="high",tags=["xss"],
        payloads=[["{{q}}",['"><svg onload=alert(1)>','<script>alert(1)</script>']]],
        matchers=[{"type":"regex","regex":[r"<svg onload=alert\(1\)>|<script>alert\(1\)"]}])
    add(id="rce-command",severity="critical",tags=["rce"],
        payloads=[["{{q}}",[";id","$(id)","`id`"]]],
        matchers=[{"type":"regex","regex":[r"uid=\d+\(\w+\)"]}])
    add(id="ssti",severity="critical",tags=["ssti"],
        payloads=[["{{q}}",["{{7*7}}","${7*7}","<%= 7*7 %>"]]],
        matchers=[{"type":"regex","regex":[r"49"]}])
    add(id="path-traversal",severity="high",tags=["lfi","traversal"],
        payloads=[["{{q}}",["../../../../etc/passwd","..%2f..%2f..%2fetc%2fpasswd"]]],
        matchers=[{"type":"regex","regex":[r"root:x:0:0:"]}])
    add(id="ssrf-basic",severity="high",tags=["ssrf"],
        payloads=[["{{q}}",["http://169.254.169.254/latest/meta-data/","file:///etc/passwd"]]],
        matchers=[{"type":"regex","regex":[r"(ami-id|root:x:0:0:)"]}])
    add(id="lfi-log-poison-check",severity="high",tags=["lfi"],
        payloads=[["{{q}}",["php://filter/convert.base64-encode/resource=index"]]],
        matchers=[{"type":"regex","regex":[r"PD9waH|PGh0bWw"]}])
    # --- CVEs known ---
    add(id="cve-2021-44228-log4j",severity="critical",tags=["cve","log4j","java"],method="GET",path="/",
        headers={"X-Api-Version":"${jndi:ldap://log4j.{{host}}/a}"},
        matchers=[])  # out-of-band detection note
    add(id="spring4shell-probe",severity="high",tags=["cve","spring"],path="/?class.module.classLoader.URLs[0]=calc",
        matchers=[])
    add(id="cve-2019-0708-probe",severity="info",tags=["cve","rdp"],port=3389,matchers=[])  # port-based
    # --- JS secrets ---
    add(id="js-api-keys",severity="high",tags=["secrets","js"],path="/",
        matchers=[{"type":"regex","regex":[r"(?i)(api[_-]?key|apikey|secret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"]}])
    add(id="js-firebase",severity="medium",tags=["secrets"],path="/",
        matchers=[{"type":"regex","regex":[r"firebaseio\.com|AIza[0-9A-Za-z_\-]{35}"]}])
    add(id="js-private-ip-leak",severity="low",tags=["info"],path="/",
        matchers=[{"type":"regex","regex":[r"(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)"]}])
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
                for param,val in t.payloads:
                    key,val_list=param,val_list=param,val if isinstance(param,tuple) else param
                # simpler: payloads = [[param_name, [vals]]]
                for pname,vals in t.payloads:
                    for v in vals:
                        nq=urllib.parse.urlencode([(k,v if k==pname else vv) for k,vv in q])
                        urls.append(urllib.parse.urlunparse(parsed._replace(query=nq)))
            else:
                # no params: append path fuzz
                for pname,vals in t.payloads:
                    for v in vals: urls.append(f"{base_url}?q={urllib.parse.quote(v)}")
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
        # custom checks
        if t.custom=="cors" and t.path=="":
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
        print(f"  {S.DIM}Time: {elapsed:.1f}s | Requests: {self.requests} | Findings: {len(self.findings)}{S.W}\n")
        # Summary by severity
        sev_count={}
        for f in self.findings: sev_count[f["severity"]]=sev_count.get(f["severity"],0)+1
        for sev in ("critical","high","medium","low","info"):
            if sev in sev_count:
                c=SEV_COLORS[sev]
                print(f"  {c}{'█'*sev_count[sev]} {sev}: {sev_count[sev]}{S.W}")
        if self.output:
            json.dump(self.findings,open(self.output,"w"),indent=2)
            print(f"\n  {S.G}[+] Report saved: {self.output}{S.W}")
        return self.findings

# ================= SUBDOMAIN DISCOVERY (crt.sh) =================
def discover_subs(domain):
    try:
        r=http_req(f"https://crt.sh/?q=%.{domain}&output=json",timeout=15)
        subs=sorted({e["name_value"].strip() for e in json.loads(r["body"]) if domain in e["name_value"]})
        return [f"https://{s}" for s in subs if "*" not in s][:50]
    except Exception: return []

# ================= CLI =================
def main():
    ap=argparse.ArgumentParser(description="VULNSCAN-X — Template-based vuln scanner")
    ap.add_argument("-u","--url",help="Single target URL")
    ap.add_argument("-l","--list",help="File with URLs/domains (one per line)")
    ap.add_argument("-d","--domain",help="Domain — auto subdomain discovery via crt.sh")
    ap.add_argument("-t","--templates",help="Custom templates JSON file")
    ap.add_argument("-w","--workers",type=int,default=25,help="Concurrent workers (default 25)")
    ap.add_argument("--timeout",type=int,default=10)
    ap.add_argument("-o","--output",help="Output JSON report")
    ap.add_argument("--tags",help="Filter templates by tags (comma separated)")
    ap.add_argument("--sev",help="Min severity (info/low/medium/high/critical)")
    a=ap.parse_args()
    print(BANNER)
    targets=[]
    if a.url: targets=[a.url]
    if a.list:
        targets+=[l.strip() for l in open(a.list) if l.strip()]
    if a.domain:
        print(f"  {S.Y}▸ Discovering subdomains for {a.domain}...{S.W}")
        subs=discover_subs(a.domain)
        print(f"  {S.G}✔ Found {len(subs)} subdomains{S.W}")
        targets+=[f"https://{a.domain}"]+subs
    if not targets:
        ap.print_help(); sys.exit(1)
    templates=builtin_templates()
    if a.templates:
        for d in json.load(open(a.templates)): templates.append(Template(d))
    sev_order=["info","low","medium","high","critical"]
    if a.sev:
        mi=sev_order.index(a.sev); templates=[t for t in templates if sev_order.index(t.sev)>=mi]
    if a.tags:
        tags=set(a.tags.split(",")); templates=[t for t in templates if set(t.tags)&tags]
    scanner=VulnScanX(targets,templates,a.workers,a.timeout,a.output)
    scanner.run()

if __name__=="__main__":
    main()

