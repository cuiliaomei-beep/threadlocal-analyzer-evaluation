package tld2;

import soot.SootMethod;
import soot.Unit;

import java.util.*;

/** Obligation predicates O1–O4 (FSE-PLAN §3.4) evaluated over the facts and typestate results. */
public final class Obligations {
    public static final class Warning {
        public String rule;
        public final Set<String> obligations = new TreeSet<>();
        public String dominant, severity, tier = "REPORT";   // tier: REPORT | WARNING | NOTE
        public String tl, tlKind, tlDeclClass, tlRuntimeClass, method, methodClass;
        public int line;
        public String detail;
        public List<String> sites;   // aggregated warning: further locations (method signatures) sharing the same finding
        public Map<String, Object> facts;
    }

    private final Program p;
    private final TLFinder finder;
    private final Typestate ts;
    private final Facts facts;
    private final Model model;
    public final List<Warning> warnings = new ArrayList<>();

    public Obligations(Program p, TLFinder finder, Typestate ts, Facts facts) {
        this.p = p; this.finder = finder; this.ts = ts; this.facts = facts; this.model = p.model;
    }

    public void run() {
        for (TL tl : finder.tls) evaluate(tl);
    }

    private static String outer(String cls) { return cls.split("\\$")[0]; }

    private void evaluate(TL tl) {
        boolean classic = model.classicTypestate;
        boolean shortOnly = !classic && tl.ctx.size() == 1 && tl.ctx.contains("SHORTLIVED");
        boolean lingering = tl.ctx.contains("CONTAINER") || tl.ctx.contains("LONGLIVED") || tl.ctx.contains("UNKNOWN") || tl.ctx.contains("POOLED");
        boolean hasRemove = tl.hasAnyAccess(TL.AKind.REMOVE);
        boolean hasSet = tl.hasAnyAccess(TL.AKind.SET);
        boolean hasSetNull = tl.hasAnyAccess(TL.AKind.SET_NULL);
        boolean isStaticLike = tl.isStatic;

        // removers: any method that removes or restores ℓ (existence of a cleanup path at all)
        // mustClearers: methods whose every exit leaves ℓ cleared/restored (a reliable cleanup point)
        Set<SootMethod> removers = new LinkedHashSet<>(), mustClearers = new LinkedHashSet<>();
        for (TL.Access a : tl.accesses) if (a.kind == TL.AKind.REMOVE || (a.kind == TL.AKind.SET && ts.restoreSets.contains(a.unit))) removers.add(a.method);
        for (Map.Entry<SootMethod, Typestate.MethodResult> e : ts.results.entrySet()) {
            Typestate.Summary s = e.getValue().exits.get(tl);
            if (s != null && s.clearsAll()) mustClearers.add(e.getKey());
        }
        Set<SootMethod> lifecycleClearers = new LinkedHashSet<>(), hostEndClearers = new LinkedHashSet<>();
        for (SootMethod m : mustClearers) {
            if (model.lifecycleEndNames.matcher(m.getName()).matches()) lifecycleClearers.add(m);
            if ((model.lifecycleEndNames.matcher(m.getName()).matches() || model.endNames.matcher(m.getName()).matches())
                    && outer(m.getDeclaringClass().getName()).equals(outer(tl.declClassName()))) hostEndClearers.add(m);
        }
        boolean lazyInstall = false;
        for (TL.Access a : tl.accesses) if (a.kind == TL.AKind.SET && ts.lazySets.contains(a.unit)) lazyInstall = true;
        boolean lazy = tl.lazyInit || lazyInstall;
        boolean churnHost = tl.kind == TL.Kind.FIELD && !tl.isStatic && tl.host.equals("CHURN");
        boolean perCallAlloc = tl.kind == TL.Kind.ALLOC && tl.allocMethod != null && !tl.allocMethod.getName().equals("<init>") && !tl.allocMethod.getName().equals("<clinit>");

        // ---------- O1 at ℓ level: nothing anywhere ever clears ℓ ----------
        if (removers.isEmpty() && (hasSet || hasSetNull) && !shortOnly) {
            TL.Access first = null;
            for (TL.Access a : tl.accesses) if (a.kind == TL.AKind.SET) { first = a; break; }
            if (first == null) for (TL.Access a : tl.accesses) if (a.kind == TL.AKind.SET_NULL) { first = a; break; }
            Warning w = base(tl, first.method, first.unit);
            w.rule = "O1_NO_CLEARER";
            w.obligations.add("O1");
            if (churnHost || perCallAlloc) w.obligations.add("O4");
            w.severity = !hasSet ? "low" : (tl.loader.equals("APP") ? "high" : "medium");
            Set<String> installers = new TreeSet<>();
            for (TL.Access a : tl.accesses) if (a.kind == TL.AKind.SET || a.kind == TL.AKind.SET_NULL) installers.add(a.method.getDeclaringClass().getShortName() + "." + a.method.getName());
            w.detail = "no remove()/restore anywhere in the jar; install sites " + installers + (lazyInstall ? "; lazy-init installs" : "") + "; ctx=" + tl.ctx;
            finish(w);
        }

        // distance (caller hops) from each method to the nearest install site of ℓ
        Map<SootMethod, Integer> dist = new HashMap<>();
        Deque<SootMethod> dq = new ArrayDeque<>();
        for (TL.Access a : tl.accesses) if ((a.kind == TL.AKind.SET || a.kind == TL.AKind.SET_NULL) && dist.putIfAbsent(a.method, 0) == null) dq.add(a.method);
        while (!dq.isEmpty()) {
            SootMethod m = dq.poll();
            int d = dist.get(m);
            if (d >= Math.max(model.reportDepth, model.entryReportDepth) + 1) continue;
            for (SootMethod c : p.callersOf(m)) if (dist.putIfAbsent(c, d + 1) == null) dq.add(c);
        }
        int suppressedFar = 0, suppressedHost = 0;
        // far task entries (reportDepth < dist <= entryReportDepth) are aggregated into one warning per ThreadLocal
        List<Object[]> farEntries = new ArrayList<>();   // {SootMethod, dist, Summary}

        // ---------- O1 / O2 per method ----------
        for (Map.Entry<SootMethod, Typestate.MethodResult> e : ts.results.entrySet()) {
            SootMethod m = e.getKey();
            Typestate.Summary s = e.getValue().exits.get(tl);
            if (s == null || !s.leaks()) continue;
            boolean localSet = tl.hasAccess(m, TL.AKind.SET) || tl.hasAccess(m, TL.AKind.SET_NULL);
            boolean localClear = ts.clearsAfterInstall(m, tl);
            boolean entry = facts.isEntry(m);
            boolean root = p.callersOf(m).isEmpty();
            boolean installerShaped = m.isConstructor() || m.getName().equals("<clinit>") || model.installerNames.matcher(m.getName()).matches();
            Integer d = dist.get(m);
            boolean near = d != null && d <= model.reportDepth;
            boolean nearEntry = d != null && d <= model.entryReportDepth;
            // per-instance ThreadLocal on a short-lived host whose end method clears it: the host lifecycle is the boundary
            if (!classic && churnHost && !hostEndClearers.isEmpty() && outer(m.getDeclaringClass().getName()).equals(outer(tl.declClassName()))) { suppressedHost++; continue; }
            String rule = null;
            if (entry && !near && nearEntry && !shortOnly) { farEntries.add(new Object[]{m, d, s}); continue; }
            if (removers.isEmpty()) {
                if (entry && near) rule = "O1_ENTRY_LEAK";          // boundary location for the ℓ-level NO_CLEARER report
                else continue;
            } else if (localSet && localClear) rule = "O1_LOCAL_INCOMPLETE";
            else if (entry && near) rule = "O1_ENTRY_LEAK";
            else if (root && near && !installerShaped && (m.isPublic() || m.isProtected())) rule = "O1_ROOT_LEAK";
            else if ((entry || root) && !near) suppressedFar++;
            if (rule == null) {
                if (root && installerShaped && localSet) note(tl, m, unitOfFirstAccess(tl, m), "API_PAIR", "install in " + m.getName() + " with clearer(s) " + names(removers));
                continue;
            }
            if (shortOnly) { note(tl, m, unitOfFirstAccess(tl, m), "O1_SHORTLIVED_ONLY", rule); continue; }
            Warning w = base(tl, m, unitOfFirstAccess(tl, m));
            w.rule = rule;
            w.obligations.add("O1");
            if (s.savedLeak()) { w.obligations.add("O2"); w.rule += "+O2_UNBALANCED_RESTORE"; }
            if ((churnHost || perCallAlloc) && hostEndClearers.isEmpty()) w.obligations.add("O4");
            w.severity = s.onlyNullLeak() ? "low" : (tl.loader.equals("APP") ? "high" : "medium");
            w.detail = (s.leaksNormal() ? "normal-exit " + s.normal : "") + (s.leaksExc() ? " exceptional-exit " + s.exc : "")
                    + (entry ? " entry=" + facts.classify(m) : "") + (root ? " root" : "") + (localClear ? " has-local-clear" : "") + (d != null ? " dist=" + d : "");
            finish(w);
        }
        if (!farEntries.isEmpty()) {
            farEntries.sort((x, y) -> Integer.compare((Integer) x[1], (Integer) y[1]));
            SootMethod m0 = (SootMethod) farEntries.get(0)[0];
            Typestate.Summary s0 = (Typestate.Summary) farEntries.get(0)[2];
            Warning w = base(tl, m0, firstUnit(m0));
            w.rule = "O1_ENTRY_LEAK_FAR";
            w.obligations.add("O1");
            if ((churnHost || perCallAlloc) && hostEndClearers.isEmpty()) w.obligations.add("O4");
            boolean onlyNull = true;
            for (Object[] fe : farEntries) if (!((Typestate.Summary) fe[2]).onlyNullLeak()) onlyNull = false;
            w.severity = onlyNull ? "low" : (tl.loader.equals("APP") ? "high" : "medium");
            w.sites = new ArrayList<>();
            for (Object[] fe : farEntries) { if (w.sites.size() >= 40) break; w.sites.add("d=" + fe[1] + " " + ((SootMethod) fe[0]).getSignature()); }
            w.detail = farEntries.size() + " task/entry methods " + (model.reportDepth + 1) + ".." + model.entryReportDepth + " caller hops from an install site exit with the value installed; nearest: " + m0.getSignature() + " " + s0.normal + "/" + s0.exc;
            finish(w);
        }
        if (suppressedFar > 0) note(tl, null, null, "O1_FAR_LEAKS_SUPPRESSED", suppressedFar + " entry/root methods leak more than " + model.entryReportDepth + " caller hops from an install site");
        if (suppressedHost > 0) note(tl, null, null, "O1_HOST_LIFECYCLE_CLEARED", suppressedHost + " leaking methods on a short-lived host whose end method(s) clear: " + names(hostEndClearers));

        // asymmetric end methods in the declaring class (H0351): some end methods clear ℓ, siblings do not
        if (!classic && tl.kind == TL.Kind.FIELD && (hasSet || lazy) && !shortOnly) {
            List<SootMethod> ends = new ArrayList<>(), clearingEnds = new ArrayList<>();
            List<SootMethod> group = new ArrayList<>();
            String og = outer(tl.declClassName());
            Set<soot.SootClass> accessing = new HashSet<>();
            for (TL.Access a : tl.accesses) accessing.add(a.method.getDeclaringClass());
            for (soot.SootClass c : p.appClasses) if (c.equals(tl.declClass) || (outer(c.getName()).equals(og) && accessing.contains(c))) group.addAll(c.getMethods());
            for (SootMethod m : group) {
                if (m.isStatic() || !p.bodies.containsKey(m) || !model.endNames.matcher(m.getName()).matches()) continue;
                if (m.getName().equals("remove") || m.getName().equals("clear") || m.getName().equals("reset") || m.getName().equals("restore") || m.getName().equals("pop")) continue;
                ends.add(m);
                if (mustClearers.contains(m)) clearingEnds.add(m);
            }
            if (!clearingEnds.isEmpty() && clearingEnds.size() < ends.size()) {
                for (SootMethod m : ends) {
                    if (clearingEnds.contains(m)) continue;
                    Warning w = base(tl, m, firstUnit(m));
                    w.rule = "O1_ASYM_END";
                    w.obligations.add("O1");
                    w.severity = "medium";
                    w.detail = "end method " + m.getName() + " does not clear; sibling(s) " + names(clearingEnds) + " do";
                    finish(w);
                }
            }
        }

        // ---------- O2: inheritance into pooled threads ----------
        if (tl.inheritable && !classic) {
            if (p.createsPoolsOrThreads || !p.delegationSites.isEmpty()) {
                Warning w = base(tl, null, null);
                w.rule = "O2_INHERIT_POOL";
                w.obligations.add("O2");
                w.severity = "medium";
                w.detail = "InheritableThreadLocal; jar creates threads/pools or delegates work (" + p.delegationSites.size() + " delegation sites)";
                finish(w);
            } else note(tl, null, null, "O2_INHERITABLE", "InheritableThreadLocal without pool creation in this jar");
        }

        // ---------- O3: declaration reachability vs value class loader ----------
        if (!classic && (tl.kind == TL.Kind.FIELD || tl.kind == TL.Kind.SELF)) {
            boolean reachLong = isStaticLike || tl.host.equals("LONGLIVED") || tl.outerCapture;
            // retention by design: no removal path at all, lazily (re)created values, or set without any remove
            boolean retainedByDesign = removers.isEmpty() || lazy || (hasSet && !hasRemove);
            boolean lifecycleHook = !lifecycleClearers.isEmpty();
            if (reachLong && retainedByDesign && lingering && !shortOnly) {
                if (tl.loader.equals("APP")) {
                    Warning w = base(tl, null, null);
                    w.rule = "O3_PIN";          // a lifecycle hook's remove() runs on one thread only; it is recorded, not exempting
                    w.tier = "REPORT";
                    w.obligations.add("O3");
                    w.severity = "high";
                    w.detail = "value types " + tl.valueTypes + (isStaticLike ? "; static" : "; host=" + tl.host) + (tl.outerCapture ? "; captures outer" : "")
                            + (lazy ? "; lazy" : "") + "; ctx=" + tl.ctx + (removers.isEmpty() ? "; no remover" : "; removers=" + names(removers))
                            + (lifecycleHook ? "; lifecycle clearers=" + names(lifecycleClearers) : "") + (tl.contentCleared ? "; content cleared per use" : "");
                    finish(w);
                } else if (tl.loader.equals("UNKNOWN")) {
                    Warning w = base(tl, null, null);
                    w.rule = "O3_PIN_UNKNOWN_VALUE";
                    w.tier = "WARNING";
                    w.obligations.add("O3");
                    w.severity = "medium";
                    w.detail = "value class unknown (" + tl.valueTypes + (tl.valueUnknownFactory ? ", pluggable factory" : "") + "); " + (isStaticLike ? "static" : "host=" + tl.host);
                    finish(w);
                } else if (tl.keyApp && isStaticLike) {
                    note(tl, null, null, "O3_KEY_ONLY", "JDK value; ThreadLocal subclass key " + (tl.runtimeClass == null ? "" : tl.runtimeClass.getName()));
                }
            }
        }

        // ---------- O4: boundedness ----------
        if (!classic && !shortOnly && tl.kind != TL.Kind.FACADE) {
            if ((churnHost && hostEndClearers.isEmpty() && (hasSet || lazy)) || perCallAlloc) {
                Warning w = base(tl, tl.kind == TL.Kind.ALLOC ? tl.allocMethod : null, tl.kind == TL.Kind.ALLOC ? tl.allocUnit : null);
                w.rule = perCallAlloc ? "O4_KEY_CHURN_ALLOC" : "O4_KEY_CHURN";
                w.obligations.add("O4");
                if (!hasRemove) w.obligations.add("O1");
                w.severity = tl.loader.equals("APP") ? "high" : "medium";
                w.detail = perCallAlloc ? "ThreadLocal allocated per call in " + tl.allocMethod.getName() + " (key churn); accesses " + accessSummary(tl)
                        : "per-instance ThreadLocal on short-lived host (" + tl.hostReason + "); no remove in an end method" + (removers.isEmpty() ? "; no remover at all" : "");
                finish(w);
            }
            if (!tl.reassignedIn.isEmpty()) {
                Warning w = base(tl, tl.reassignedIn.get(0), firstUnit(tl.reassignedIn.get(0)));
                w.rule = "O4_KEY_REASSIGN";
                w.obligations.add("O4");
                boolean removesOld = false;
                for (SootMethod m : tl.reassignedIn) if (tl.hasAccess(m, TL.AKind.REMOVE)) removesOld = true;
                if (!removesOld) w.obligations.add("O1");
                w.severity = tl.loader.equals("APP") ? "high" : "medium";
                w.detail = "ThreadLocal field re-assigned in " + names(tl.reassignedIn) + " (old per-thread entries keep their values)" + (removesOld ? "; old value removed" : "");
                finish(w);
            }
            boolean perUseCleared = anyPerUseClear(tl, mustClearers) || (tl.contentCleared && !tl.bufferValue);
            if (tl.growable && !tl.softWrapped && (lazy || !hasRemove) && !perUseCleared) {
                Warning w = base(tl, null, null);
                w.rule = "O4_UNBOUNDED_VALUE";
                w.obligations.add("O4");
                w.severity = "medium";
                w.detail = "growable value " + tl.valueTypes + " retained per thread without remove/shrink; " + (lazy ? "lazy-initialised" : "");
                finish(w);
            }
        }
    }

    private static String accessSummary(TL tl) {
        Map<String, Integer> ac = new TreeMap<>();
        for (TL.Access a : tl.accesses) ac.merge(a.kind.name(), 1, Integer::sum);
        return ac.toString();
    }

    private boolean anyPerUseClear(TL tl, Set<SootMethod> clearers) {
        for (SootMethod m : clearers) if (tl.hasAccess(m, TL.AKind.SET) || tl.hasAccess(m, TL.AKind.GET)) return true;
        return false;
    }

    private Unit unitOfFirstAccess(TL tl, SootMethod m) {
        for (TL.Access a : tl.accesses) if (a.method.equals(m) && (a.kind == TL.AKind.SET || a.kind == TL.AKind.SET_NULL)) return a.unit;
        for (TL.Access a : tl.accesses) if (a.method.equals(m)) return a.unit;
        return firstUnit(m);
    }

    private Unit firstUnit(SootMethod m) {
        soot.Body b = p.bodies.get(m);
        if (b == null) return null;
        for (Unit u : b.getUnits()) if (Program.line(u) > 0) return u;
        return b.getUnits().isEmpty() ? null : b.getUnits().getFirst();
    }

    private static String names(Collection<SootMethod> ms) {
        List<String> out = new ArrayList<>();
        for (SootMethod m : ms) { out.add(m.getDeclaringClass().getShortName() + "." + m.getName()); if (out.size() >= 4) break; }
        return out.toString();
    }

    private Warning base(TL tl, SootMethod m, Unit u) {
        Warning w = new Warning();
        w.tl = tl.id;
        w.tlKind = tl.kind.name();
        w.tlDeclClass = tl.declClassName();
        w.tlRuntimeClass = tl.runtimeClass == null ? null : tl.runtimeClass.getName();
        if (m != null) {
            w.method = m.getSignature();
            w.methodClass = m.getDeclaringClass().getName();
            w.line = u == null ? 0 : Program.line(u);
        } else {
            w.method = null;
            w.methodClass = tl.declClassName();
            w.line = 0;
        }
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("static", tl.isStatic);
        f.put("host", tl.host);
        f.put("hostReason", tl.hostReason);
        f.put("loader", tl.loader);
        f.put("valueTypes", new ArrayList<>(tl.valueTypes));
        f.put("growable", tl.growable);
        f.put("softWrapped", tl.softWrapped);
        f.put("ctx", new ArrayList<>(tl.ctx));
        f.put("inheritable", tl.inheritable);
        f.put("outerCapture", tl.outerCapture);
        f.put("keyApp", tl.keyApp);
        f.put("lazyInit", tl.lazyInit);
        f.put("withInitial", tl.withInitial);
        w.facts = f;
        return w;
    }

    private void note(TL tl, SootMethod m, Unit u, String rule, String detail) {
        Warning w = base(tl, m, u);
        w.rule = rule;
        w.tier = "NOTE";
        w.severity = "none";
        w.detail = detail;
        w.dominant = "-";
        warnings.add(w);
    }

    private void finish(Warning w) {
        if (model.classicTypestate) { w.obligations.retainAll(Collections.singleton("O1")); w.rule = w.rule.split("\\+")[0]; w.severity = "n/a"; }
        for (String d : new String[]{"O3", "O2", "O4", "O1"}) if (w.obligations.contains(d)) { w.dominant = d; break; }
        warnings.add(w);
    }
}
