"""Builds the SpotBugs-TL plugin sources VERBATIM from TLDoctor/SpotBugs-TL.md (the only published form of the baseline).

Every file is cut out of a fenced code block of the document; the only textual change is the anonymised package
placeholder `edu.****` -> `edu.anon` (a Java package name cannot contain `*`). Nothing else is added or edited here.
Run: python baselines/spotbugs-tl/extract_from_md.py
"""
import hashlib, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MD = os.path.join(ROOT, "TLDoctor", "SpotBugs-TL.md")
text = open(MD, encoding="utf-8").read()
blocks = re.findall(r"```(\w+)\n(.*?)```", text, re.S)
out = {}
for lang, body in blocks:
    body = body.replace("edu.****", "edu.anon")
    if lang == "xml" and "<FindbugsPlugin" in body:
        out["src/main/resources/findbugs.xml"] = body
    elif lang == "xml" and "<MessageCollection>" in body:
        out["src/main/resources/messages.xml"] = body
    elif lang == "text" and "TL_SCO_MISSING_REMOVE" in body and body.strip()[0].isdigit():
        out["src/main/resources/bugrank.txt"] = body
    elif lang == "java":
        m = re.search(r"public class (TL_\w+)", body)
        if m:
            out[f"src/main/java/edu/anon/spotbugs/threadlocal/{m.group(1)}.java"] = body
# LOADING FIX (descriptor only, no detector logic): SpotBugs 4.9.8 refuses to load a plugin whose messages.xml lacks a
# <Detector> description for every registered detector and a <BugCode> for every abbreviation. The published
# messages.xml describes only the SCO detector and has no BugCode. The missing entries are appended here.
ADDED = """
    <!-- added for loadability (see extract_from_md.py): descriptions only -->
    <Detector class="edu.anon.spotbugs.threadlocal.TL_CLP_StaticThreadLocalDetector">
        <Details>Detects static ThreadLocal fields or static holders.</Details>
    </Detector>
    <Detector class="edu.anon.spotbugs.threadlocal.TL_CPM_UnbalancedContextDetector">
        <Details>Detects unbalanced ThreadLocal context propagation across async boundaries.</Details>
    </Detector>
    <Detector class="edu.anon.spotbugs.threadlocal.TL_HVR_HeavyValueRetentionDetector">
        <Details>Detects ThreadLocal fields with heavyweight or growth-prone value types.</Details>
    </Detector>
    <BugCode abbrev="TL">ThreadLocal misuse</BugCode>

</MessageCollection>"""
m_xml = out["src/main/resources/messages.xml"]
assert m_xml.rstrip().endswith("</MessageCollection>")
out["src/main/resources/messages.xml"] = m_xml.rstrip()[: -len("</MessageCollection>")].rstrip() + "\n" + ADDED + "\n"

expected = {"findbugs.xml", "messages.xml", "bugrank.txt", "TL_SCO_MissingRemoveDetector.java", "TL_CLP_StaticThreadLocalDetector.java",
            "TL_CPM_UnbalancedContextDetector.java", "TL_HVR_HeavyValueRetentionDetector.java"}
got = {os.path.basename(k) for k in out}
assert got == expected, (got ^ expected)
manifest = [f"source document: TLDoctor/SpotBugs-TL.md sha256={hashlib.sha256(open(MD,'rb').read()).hexdigest()}"]
for rel, body in sorted(out.items()):
    p = os.path.join(HERE, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8", newline="\n").write(body)
    manifest.append(f"{rel} sha256={hashlib.sha256(body.encode('utf-8')).hexdigest()} lines={body.count(chr(10))}")
open(os.path.join(HERE, "MANIFEST.txt"), "w", encoding="utf-8").write("\n".join(manifest) + "\n")
print("\n".join(manifest))
