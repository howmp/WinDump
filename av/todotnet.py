import json
from pathlib import Path
# https://github.com/Aabyss-Team/Antivirus-Scan/blob/main/auto.json
items = json.loads(Path("auto.json").read_bytes())


avmap = {}

for av, info in items.items():
    if av == "已知杀软进程,名称暂未收录":
        continue
    for process in info["processes"]:
        if "/" in process:
            continue
        if process in avmap:
            avmap[process] = av + " or " + avmap[process]
        else:
            avmap[process] = av
with Path('out.txt').open('w',encoding='utf8') as f:
    f.write('static Dictionary<string,string> av = new Dictionary<string, string> {\n')
    for process,av in avmap.items():
        f.write(f'  {{"{process}", "{av}"}},\n')
    f.write("};")