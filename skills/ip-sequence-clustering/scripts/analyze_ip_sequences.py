#!/usr/bin/env python3
"""Reproducible offline triage for repeated source-IP sequences (Python 3.10+)."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import ipaddress
import json
from pathlib import Path

def jaccard(a,b):
    a,b=set(a),set(b)
    return len(a&b)/len(a|b) if a|b else None

def kendall_tau(a,b):
    """Kendall tau-a for first-occurrence ranks on shared IPs."""
    a=list(dict.fromkeys(a)); b=list(dict.fromkeys(b))
    shared=set(a)&set(b); a=[x for x in a if x in shared]
    rank={x:i for i,x in enumerate(b)}
    n=len(a)
    if n<2: return None
    discord=sum(rank[a[i]]>rank[a[j]] for i in range(n) for j in range(i+1,n))
    return 1-4*discord/(n*(n-1))

def load(path, column=None):
    p=Path(path)
    raw=p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() in (".csv",".tsv"):
        rows=csv.DictReader(raw.splitlines(),delimiter="\t" if p.suffix.lower()==".tsv" else ",")
        names=rows.fieldnames or []
        col=column or next((s for s in ("src_ip","source_ip","remote_addr","client_ip","ip") if s in names),None)
        if col not in names: raise ValueError("Pass --ip-column matching CSV header")
        lines=[row[col] for row in rows]
    else: lines=raw.splitlines()
    ips=[]; invalid=0
    for value in lines:
        try: ips.append(str(ipaddress.ip_address(value.strip())))
        except ValueError: invalid+=1
    if not ips: raise ValueError("No valid IP records")
    return ips,invalid,hashlib.sha256(p.read_bytes()).hexdigest()

def dominant(ips):
    counts=Counter(ips)
    common=Counter(counts.values()).most_common(1)[0][0]
    return {ip for ip,n in counts.items() if n>max(10,common*5)}

def phases_by_novelty(ips, excluded):
    """Heuristic boundaries: sharp transitions from recycled to mostly unseen IPs."""
    active=[(idx,ip) for idx,ip in enumerate(ips) if ip not in excluded]
    if len(active)<30: return [(0,len(ips))]
    seen=set(); novelty=[]
    for _,ip in active:
        novelty.append(0 if ip in seen else 1); seen.add(ip)
    window=min(12,max(5,len(active)//60)); min_size=max(15,len(active)//15)
    cuts=[0]
    for i in range(window,len(active)-window):
        if i-cuts[-1]<min_size or len(active)-i<min_size: continue
        before=sum(novelty[i-window:i])/window
        after=sum(novelty[i:i+window])/window
        if before<=0.3 and after>=0.7 and after-before>=0.6: cuts.append(i)
    edges=[0]+[active[i][0] for i in cuts[1:]]+[len(ips)]
    return list(zip(edges,edges[1:]))

def cycle_windows(ips, start, stop, excluded):
    """Heuristic cycle splits, based on majority repeat count and rank resets."""
    keep=[(i,ip) for i in range(start,stop) if (ip:=ips[i]) not in excluded]
    if len(keep)<6: return [(start,stop)]
    freq=Counter(ip for _,ip in keep)
    repeats=Counter(freq.values()).most_common(1)[0][0]
    if repeats<2 or repeats>12: return [(start,stop)]
    order={ip:ix for ix,ip in enumerate(dict.fromkeys(ip for _,ip in keep))}
    ranks=[order[ip] for _,ip in keep]; period=len(keep)/repeats
    edges=[0]
    for q in range(1,repeats):
        goal=q*period
        low=max(edges[-1]+1,int(goal-period*.2))
        high=min(len(keep)-1,int(goal+period*.2))
        if low>=high: return [(start,stop)]
        spot=min(range(low,high+1),key=lambda j:(ranks[j]-ranks[j-1],abs(j-goal)*.003))
        if ranks[spot]>=ranks[spot-1]: return [(start,stop)]
        edges.append(spot)
    edges.append(len(keep))
    return [(start if a==0 else keep[a][0],stop if b==len(keep) else keep[b][0]) for a,b in zip(edges,edges[1:])]

def analyze(ips, manual=None, exclude=None, min_j=.80, min_tau=.85):
    excluded=set(exclude or dominant(ips))
    phases=manual or phases_by_novelty(ips,excluded)
    info=[]; membership=[]; locations=defaultdict(list)
    for p,(start,stop) in enumerate(phases,1):
        cycles=cycle_windows(ips,start,stop,excluded)
        scores=[]
        for i in range(len(cycles)):
            for j in range(i+1,len(cycles)):
                x=[ip for ip in ips[cycles[i][0]:cycles[i][1]] if ip not in excluded]
                y=[ip for ip in ips[cycles[j][0]:cycles[j][1]] if ip not in excluded]
                scores.append({"cycles":[i+1,j+1],"jaccard":jaccard(x,y),
                               "kendall_tau_a":kendall_tau(x,y)})
        valid=bool(scores) and all(v["jaccard"] is not None and v["jaccard"]>=min_j
                                   and v["kendall_tau_a"] is not None and v["kendall_tau_a"]>=min_tau for v in scores)
        info.append({"phase":p,"start":start+1,"end":stop,
                     "cycles":[{"start":a+1,"end":b} for a,b in cycles],
                     "validated":valid,"pairwise_scores":scores})
        for ip,n in Counter(ips[start:stop]).items():
            locations[ip].append(p)
            membership.append({"ip":ip,"phase":p,"count":n})
    anomalies=[]
    for ip in excluded:
        anomalies.append({"ip":ip,"reason":"DOMINANT","count":ips.count(ip)})
    for ip,ps in locations.items():
        if len(ps)>1 and ip not in excluded:
            anomalies.append({"ip":ip,"reason":"CROSS_PHASE","count":ips.count(ip)})
    for p,(start,stop) in enumerate(phases,1):
        freq=Counter(ip for ip in ips[start:stop] if ip not in excluded)
        if not freq: continue
        expected=Counter(freq.values()).most_common(1)[0][0]
        for ip,n in freq.items():
            if n!=expected:
                anomalies.append({"ip":ip,"reason":"FREQUENCY_DEVIATION","count":n,"phase":p,"expected":expected})
    return {"method":"analyst-supplied" if manual else "heuristic", "events":len(ips),
            "unique_ips":len(set(ips)),"excluded_dominant":sorted(excluded),
            "phases":info,"memberships":membership,"anomalies":anomalies}

def parse_manual(s,n):
    parts=[]
    for piece in s.split(","):
        a,b=map(int,piece.split("-"))
        if not 1<=a<=b<=n: raise ValueError("Invalid phase boundary")
        parts.append((a-1,b))
    if parts[0][0]!=0 or parts[-1][1]!=n or any(parts[i][1]!=parts[i+1][0] for i in range(len(parts)-1)):
        raise ValueError("Phases must cover entire input without gaps")
    return parts

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input");ap.add_argument("--out",default="results")
    ap.add_argument("--ip-column");ap.add_argument("--exclude-ip",action="append",default=[])
    ap.add_argument("--phases",help="Analyst boundaries, 1-based inclusive, e.g. 1-300,301-600")
    ap.add_argument("--min-jaccard",type=float,default=.8)
    ap.add_argument("--min-kendall",type=float,default=.85)
    a=ap.parse_args()
    ips,invalid,digest=load(a.input,a.ip_column)
    manual=parse_manual(a.phases,len(ips)) if a.phases else None
    result=analyze(ips,manual,a.exclude_ip or None,a.min_jaccard,a.min_kendall)
    result.update({"invalid_rows":invalid,"source_sha256":digest})
    dest=Path(a.out);dest.mkdir(parents=True,exist_ok=True)
    (dest/"report.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf8")
    for name,fields,key in [
        ("memberships.csv",["ip","phase","count"],"memberships"),
        ("anomalies.csv",["ip","reason","count","phase","expected"],"anomalies")]:
        with (dest/name).open("w",newline="",encoding="utf8") as fp:
            writer=csv.DictWriter(fp,fieldnames=fields,extrasaction="ignore")
            writer.writeheader();writer.writerows(result[key])
    md=["# IP Sequence Analysis","",f"Events: {len(ips)}, unique IPs: {len(set(ips))}.",
        f"Boundaries: {result['method']}; excluded dominant IPs: {len(result['excluded_dominant'])}.",
        f"SHA-256: \`{digest}\`.",""]
    for p in result["phases"]:
        vals=p["pairwise_scores"]
        md += [f"## Phase {p['phase']} ({p['start']}–{p['end']})",
               f"Candidate cycles: {len(p['cycles'])}; passes thresholds: **{p['validated']}**.",
               f"Minimum Jaccard: {min((v['jaccard'] for v in vals if v['jaccard'] is not None),default=None)}.",
               f"Minimum Kendall tau-a: {min((v['kendall_tau_a'] for v in vals if v['kendall_tau_a'] is not None),default=None)}.",""]
    md += ["**Interpretation:** Similarity validates suggested sequences, not attribution. Phase "
           "boundaries are heuristic unless supplied explicitly. Confirm the log source, "
           "request context, duplicate ingestion, and benign clients before any inference."]
    (dest/"report.md").write_text("\n".join(md)+"\n",encoding="utf8")
    print(f"Wrote report.md, report.json, memberships.csv, anomalies.csv to {dest}")
if __name__=="__main__": main()
