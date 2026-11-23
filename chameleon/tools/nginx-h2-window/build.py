# Configure and build nginx without make: runs configure, then executes the
# compile and link recipes of the generated objs/Makefile. Nothing is installed.
import os, re, subprocess, sys, concurrent.futures
root = sys.argv[1]
os.chdir(root)
if os.environ.get("CONFIGURE_ARGS_FILE"):
    # Exact configure arguments, one per line (e.g. a distribution's nginx -V).
    args = [l.strip() for l in open(os.environ["CONFIGURE_ARGS_FILE"]) if l.strip()]
else:
    args = ["--prefix=" + root + "/run",
            "--with-http_v2_module", "--without-http_rewrite_module",
            "--without-http_gzip_module", "--without-pcre",
            "--with-cc-opt=-O2 " + os.environ.get("EXTRA_CC", "")]
subprocess.run(["sh", "configure"] + args + sys.argv[2:], check=True, stdout=subprocess.DEVNULL)
text = re.sub(r"\\\n[ \t]*", " ", open("objs/Makefile").read())
vars_, rules = {}, []
current = None
for line in text.split("\n"):
    if line.startswith("\t"):
        if current is not None:
            current[2].append(line.strip())
        continue
    m = re.match(r"^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$", line)
    if m:
        vars_[m.group(1)] = m.group(2)
        current = None
        continue
    m = re.match(r"^([^\s:]+):(.*)$", line)
    if m:
        current = (m.group(1), m.group(2), [])
        rules.append(current)
def expand(s, depth=0):
    return re.sub(r"\$\((\w+)\)", lambda m: expand(vars_.get(m.group(1), ""), depth + 1), s) if depth < 10 else s
objects = [r for r in rules if r[0].endswith(".o") and r[2]]
def run(rule):
    for cmd in rule[2]:
        result = subprocess.run(expand(cmd), shell=True, capture_output=True, text=True)
        if result.returncode:
            return rule[0] + "\n" + result.stderr[-2000:]
    return None
with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
    errors = [e for e in pool.map(run, objects) if e]
if errors:
    print("COMPILE ERRORS:\n" + "\n".join(errors[:3])); sys.exit(1)
link = next(r for r in rules if r[0] == "objs/nginx")
err = run(link)
if err:
    print("LINK ERROR:\n" + err); sys.exit(1)
print(f"built {root}/objs/nginx from {len(objects)} objects")
