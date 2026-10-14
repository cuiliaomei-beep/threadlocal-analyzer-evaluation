package tld2;

import soot.*;
import soot.jimple.*;
import soot.toolkits.exceptions.ThrowableSet;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGDominatorsFinder;

import java.util.*;

/**
 * Obligation typestate (FSE-PLAN §3.2 layer 2, §3.3 transfer table).
 * Per method and per abstract ThreadLocal ℓ: σ ⊆ {PRE, INST, INST_SAVED, INST_NULL, INST_LAZY, CLEARED}; PRE = unchanged since entry.
 * Interprocedural: bottom-up summaries (exit states on normal / exceptional exits), iterated to a fixpoint.
 * Restore recognition: ℓ.set(x) with x from ℓ.get(), or a call to a helper that installs its parameter when the actual
 * argument came from ℓ.get() or from a helper that returns ℓ.get() (save-install-restore through wrappers).
 * Exceptional-exit model: a unit completes exceptionally iff it is a throw, or an invoke whose callee may throw
 * (app callee: computed; library callee: unless its class is in neverThrowPrefixes); implicit runtime exceptions
 * (NPE, AIOOBE...) are not modelled; a trap catching Throwable/Exception/RuntimeException covers all modelled exceptions.
 */
public final class Typestate {
    /** INST_LAZY: install inside a `get()==null` guard (lazy per-thread initialisation; retained by design, not an O1 leak) */
    public enum St { PRE, INST, INST_SAVED, INST_NULL, INST_LAZY, CLEARED }
    public static final EnumSet<St> INSTALLED = EnumSet.of(St.INST, St.INST_SAVED, St.INST_NULL);
    public static final EnumSet<St> RETAINED = EnumSet.of(St.INST, St.INST_SAVED, St.INST_NULL, St.INST_LAZY);

    public static final class Summary {
        public EnumSet<St> normal = EnumSet.of(St.PRE);
        public EnumSet<St> exc = EnumSet.of(St.PRE);
        boolean sameAs(Summary o) { return normal.equals(o.normal) && exc.equals(o.exc); }
        public boolean leaks() { return leaksNormal() || leaksExc(); }
        public boolean leaksNormal() { for (St s : normal) if (INSTALLED.contains(s)) return true; return false; }
        public boolean leaksExc() { for (St s : exc) if (INSTALLED.contains(s)) return true; return false; }
        public boolean lazyRetained() { return normal.contains(St.INST_LAZY) || exc.contains(St.INST_LAZY); }
        public boolean onlyNullLeak() {
            for (St s : normal) if (s == St.INST || s == St.INST_SAVED) return false;
            for (St s : exc) if (s == St.INST || s == St.INST_SAVED) return false;
            return true;
        }
        public boolean savedLeak() { return normal.contains(St.INST_SAVED) || exc.contains(St.INST_SAVED); }
        /** every exit leaves ℓ cleared (or untouched on paths that never installed) and none installed */
        public boolean clearsAll() { return !leaks() && !lazyRetained() && (normal.contains(St.CLEARED) || exc.contains(St.CLEARED)); }
    }

    public static final class MethodResult {
        public final Map<TL, Summary> exits = new HashMap<>();
        public boolean analysed;
    }

    private final Program p;
    private final TLFinder finder;
    private final Model model;
    public final Map<SootMethod, MethodResult> results = new HashMap<>();
    public final Set<SootMethod> relevant = new LinkedHashSet<>();
    private final Map<SootMethod, Boolean> mayThrow = new HashMap<>();
    /** set units recognised as restores (ℓ.set(x) with x from ℓ.get(), or restoring helper calls) */
    public final Set<Unit> restoreSets = new HashSet<>();
    /** set units recognised as lazy initialisation (`v = get(); if (v == null) set(new)`) */
    public final Set<Unit> lazySets = new HashSet<>();
    /** (method, ℓ) pairs where a remove/restore is executed while ℓ is installed in the same method (install-then-clean shape) */
    public final Map<SootMethod, Set<TL>> clearAfterInstall = new HashMap<>();
    /** methods that return ℓ.get() (previous-value accessors) */
    public final Map<SootMethod, Set<TL>> returnsGet = new HashMap<>();
    /** methods that install a parameter into ℓ: ℓ -> parameter index */
    public final Map<SootMethod, Map<TL, Integer>> installsFromParam = new HashMap<>();
    private final Map<Unit, Boolean> restoreCache = new HashMap<>();
    public int rounds = 0, graphErrors = 0;

    public Typestate(Program p, TLFinder finder) {
        this.p = p; this.finder = finder; this.model = p.model;
    }

    public void run() {
        Deque<SootMethod> work = new ArrayDeque<>();
        for (TL tl : finder.tls) for (TL.Access a : tl.accesses) if (relevant.add(a.method)) work.add(a.method);
        while (!work.isEmpty()) {
            SootMethod m = work.poll();
            for (SootMethod c : p.callersOf(m)) if (relevant.add(c)) work.add(c);
        }
        computeMayThrow();
        computeShapes();
        for (SootMethod m : relevant) results.put(m, new MethodResult());
        for (rounds = 1; rounds <= model.summaryRounds; rounds++) {
            boolean changed = false;
            for (SootMethod m : relevant) {
                Body b = p.bodies.get(m);
                if (b == null) continue;
                Map<TL, Summary> fresh;
                try {
                    fresh = analyse(m, b);
                } catch (Throwable t) {
                    graphErrors++;
                    continue;
                }
                MethodResult r = results.get(m);
                if (!r.analysed || !same(r.exits, fresh)) changed = true;
                r.exits.clear();
                r.exits.putAll(fresh);
                r.analysed = true;
            }
            if (!changed) break;
        }
    }

    private static boolean same(Map<TL, Summary> a, Map<TL, Summary> b) {
        if (!a.keySet().equals(b.keySet())) return false;
        for (TL k : a.keySet()) if (!a.get(k).sameAs(b.get(k))) return false;
        return true;
    }

    // ---------- method shapes: returns get(), installs parameter ----------
    private void computeShapes() {
        for (TL tl : finder.tls) {
            for (TL.Access a : tl.accesses) {
                Body b = p.bodies.get(a.method);
                if (b == null) continue;
                if (a.kind == TL.AKind.SET && a.arg instanceof Local) {
                    Integer idx = paramIndex((Local) a.arg, a.unit, b);
                    if (idx != null) installsFromParam.computeIfAbsent(a.method, k -> new HashMap<>()).put(tl, idx);
                }
                if (a.kind == TL.AKind.GET && a.result instanceof Local) {
                    for (Unit u : b.getUnits()) {
                        if (u instanceof ReturnStmt && ((ReturnStmt) u).getOp() instanceof Local && aliasOf(((ReturnStmt) u).getOp(), (Local) a.result, u, b))
                            returnsGet.computeIfAbsent(a.method, k -> new HashSet<>()).add(tl);
                    }
                }
            }
        }
    }

    private Integer paramIndex(Local l, Unit at, Body b) {
        try {
            List<Unit> defs = finder.defs(b).getDefsOfAt(l, at);
            if (defs.size() != 1) return null;
            Unit d = defs.get(0);
            if (d instanceof IdentityStmt && ((IdentityStmt) d).getRightOp() instanceof ParameterRef) return ((ParameterRef) ((IdentityStmt) d).getRightOp()).getIndex();
            if (d instanceof AssignStmt && ((AssignStmt) d).getRightOp() instanceof CastExpr && ((CastExpr) ((AssignStmt) d).getRightOp()).getOp() instanceof Local)
                return paramIndex((Local) ((CastExpr) ((AssignStmt) d).getRightOp()).getOp(), d, b);
        } catch (Throwable ignored) {
        }
        return null;
    }

    // ---------- may-throw (all app methods, fixpoint) ----------
    private void computeMayThrow() {
        for (SootMethod m : p.bodies.keySet()) mayThrow.put(m, false);
        for (int round = 0; round < 12; round++) {
            boolean changed = false;
            for (Map.Entry<SootMethod, Body> e : p.bodies.entrySet()) {
                if (mayThrow.get(e.getKey())) continue;
                if (bodyMayThrow(e.getValue())) {
                    mayThrow.put(e.getKey(), true);
                    changed = true;
                }
            }
            if (!changed) break;
        }
    }

    private boolean bodyMayThrow(Body b) {
        for (Unit u : b.getUnits()) {
            if (coveredByCatchAll(b, u)) continue;
            if (u instanceof ThrowStmt) return true;
            Stmt s = (Stmt) u;
            if (s.containsInvokeExpr() && unitMayThrow(u, s.getInvokeExpr())) return true;
        }
        return false;
    }

    private boolean unitMayThrow(Unit u, InvokeExpr ie) {
        if (finder.accessAt.containsKey(u)) return false;
        if (p.unresolved.contains(u)) return true;
        Set<SootMethod> ts = p.targets.getOrDefault(u, Collections.emptySet());
        if (ts.isEmpty()) return !model.neverThrows(ie.getMethodRef().getDeclaringClass().getName());
        for (SootMethod t : ts) {
            if (p.bodies.containsKey(t)) {
                if (Boolean.TRUE.equals(mayThrow.get(t))) return true;
            } else if (!model.neverThrows(t.getDeclaringClass().getName())) return true;
        }
        return false;
    }

    private boolean coveredByCatchAll(Body b, Unit u) {
        for (Trap t : b.getTraps()) {
            String ex = t.getException().getName();
            if (!(ex.equals("java.lang.Throwable") || ex.equals("java.lang.Exception") || ex.equals("java.lang.RuntimeException"))) continue;
            if (inRange(b, t.getBeginUnit(), t.getEndUnit(), u)) return true;
        }
        return false;
    }

    private boolean inRange(Body b, Unit begin, Unit end, Unit u) {
        Unit x = begin;
        while (x != null && x != end) {
            if (x == u) return true;
            x = b.getUnits().getSuccOf(x);
        }
        return false;
    }

    // ---------- intraprocedural flow ----------
    private Map<TL, Summary> analyse(SootMethod m, Body b) {
        ExceptionalUnitGraph g = new ExceptionalUnitGraph(b);
        MHGDominatorsFinder<Unit> dom = new MHGDominatorsFinder<>(g);
        Map<Unit, Map<TL, EnumSet<St>>> in = new HashMap<>();
        Deque<Unit> work = new ArrayDeque<>();
        for (Unit h : g.getHeads()) { in.put(h, new HashMap<>()); work.add(h); }
        Map<TL, Summary> exits = new HashMap<>();
        Set<Unit> inWork = new HashSet<>(work);
        int steps = 0;
        while (!work.isEmpty()) {
            Unit u = work.poll();
            inWork.remove(u);
            if (++steps > 200000) break;
            Map<TL, EnumSet<St>> cur = in.getOrDefault(u, Collections.emptyMap());
            Map<TL, EnumSet<St>> normal = copy(cur);
            Map<TL, EnumSet<St>> exc = copy(cur);
            transfer(m, b, dom, u, cur, normal, exc);
            if (u instanceof ReturnStmt || u instanceof ReturnVoidStmt) {
                for (Map.Entry<TL, EnumSet<St>> e : normal.entrySet()) sum(exits, e.getKey()).normal.addAll(e.getValue());
            }
            if (escapes(g, b, u)) {
                for (Map.Entry<TL, EnumSet<St>> e : exc.entrySet()) sum(exits, e.getKey()).exc.addAll(e.getValue());
            }
            for (Unit s : g.getUnexceptionalSuccsOf(u)) if (merge(in, s, normal) && inWork.add(s)) work.add(s);
            for (Unit s : g.getExceptionalSuccsOf(u)) {
                boolean ch = merge(in, s, cur);
                ch |= merge(in, s, exc);
                if (ch && inWork.add(s)) work.add(s);
            }
        }
        for (Summary s : exits.values()) {
            if (s.normal.isEmpty()) s.normal.add(St.PRE);
            if (s.exc.isEmpty()) s.exc.add(St.PRE);
        }
        return exits;
    }

    private static Summary sum(Map<TL, Summary> exits, TL tl) {
        return exits.computeIfAbsent(tl, k -> { Summary s = new Summary(); s.normal = EnumSet.noneOf(St.class); s.exc = EnumSet.noneOf(St.class); return s; });
    }

    private static Map<TL, EnumSet<St>> copy(Map<TL, EnumSet<St>> m) {
        Map<TL, EnumSet<St>> out = new HashMap<>();
        for (Map.Entry<TL, EnumSet<St>> e : m.entrySet()) out.put(e.getKey(), e.getValue().clone());
        return out;
    }

    private static boolean merge(Map<Unit, Map<TL, EnumSet<St>>> in, Unit s, Map<TL, EnumSet<St>> add) {
        Map<TL, EnumSet<St>> tgt = in.get(s);
        if (tgt == null) { in.put(s, copy(add)); return true; }
        boolean ch = false;
        for (Map.Entry<TL, EnumSet<St>> e : add.entrySet()) {
            EnumSet<St> t = tgt.get(e.getKey());
            if (t == null) { tgt.put(e.getKey(), e.getValue().clone()); ch = true; }
            else if (t.addAll(e.getValue())) ch = true;
        }
        for (Map.Entry<TL, EnumSet<St>> e : tgt.entrySet()) if (!add.containsKey(e.getKey()) && e.getValue().add(St.PRE)) ch = true;
        return ch;
    }

    private void noteClearAfterInstall(SootMethod m, TL tl, EnumSet<St> before) {
        for (St s : before) if (INSTALLED.contains(s)) { clearAfterInstall.computeIfAbsent(m, k -> new HashSet<>()).add(tl); return; }
    }

    private void transfer(SootMethod m, Body b, MHGDominatorsFinder<Unit> dom, Unit u,
                          Map<TL, EnumSet<St>> cur, Map<TL, EnumSet<St>> normal, Map<TL, EnumSet<St>> exc) {
        TL.Access a = finder.accessAt.get(u);
        if (a != null) {
            EnumSet<St> before = cur.getOrDefault(a.tl, EnumSet.of(St.PRE));
            switch (a.kind) {
                case SET_NULL:
                    if (model.classicTypestate) { normal.put(a.tl, EnumSet.of(St.INST)); break; }
                    normal.put(a.tl, EnumSet.of(St.INST_NULL)); noteClearAfterInstall(m, a.tl, before); break;
                case REMOVE: normal.put(a.tl, EnumSet.of(St.CLEARED)); noteClearAfterInstall(m, a.tl, before); break;
                case SET:
                    if (model.classicTypestate) { normal.put(a.tl, EnumSet.of(St.INST)); break; }
                    if (isRestore(a, b)) { normal.put(a.tl, EnumSet.of(St.PRE)); noteClearAfterInstall(m, a.tl, before); }
                    else if (!model.ablLazy && isLazyInit(a, b, dom)) { normal.put(a.tl, EnumSet.of(St.INST_LAZY)); lazySets.add(a.unit); }
                    else normal.put(a.tl, EnumSet.of(!model.ablRestore && savedBefore(a, b, dom) ? St.INST_SAVED : St.INST));
                    break;
                default: break;
            }
            exc.clear(); exc.putAll(copy(cur));
            return;
        }
        if (model.ablSummaries) return;      // ablation: intraprocedural, a call leaves the state unchanged
        Stmt s = (Stmt) u;
        if (!s.containsInvokeExpr()) return;
        Set<SootMethod> ts = p.appTargets(u);
        if (ts.isEmpty()) return;
        InvokeExpr ie = s.getInvokeExpr();
        // restore through a helper: callee installs parameter i and the actual argument is the saved previous value
        Set<TL> restored = new HashSet<>(), nulled = new HashSet<>();
        for (SootMethod t : ts) {
            Map<TL, Integer> ip = model.classicTypestate ? null : installsFromParam.get(t);
            if (ip == null) continue;
            for (Map.Entry<TL, Integer> e : ip.entrySet()) {
                if (e.getValue() >= ie.getArgCount()) continue;
                Value arg = ie.getArg(e.getValue());
                if (arg instanceof NullConstant) nulled.add(e.getKey());
                else if (!model.ablRestore && arg instanceof Local && fromSavedPrevious((Local) arg, u, b, e.getKey())) restored.add(e.getKey());
            }
        }
        Set<TL> keys = new HashSet<>();
        List<MethodResult> rs = new ArrayList<>();
        for (SootMethod t : ts) {
            MethodResult r = results.get(t);
            if (r != null && r.analysed) { rs.add(r); keys.addAll(r.exits.keySet()); }
            else rs.add(null);
        }
        keys.addAll(restored); keys.addAll(nulled);
        for (TL tl : keys) {
            EnumSet<St> c = cur.getOrDefault(tl, EnumSet.of(St.PRE));
            if (restored.contains(tl)) { normal.put(tl, EnumSet.of(St.PRE)); exc.put(tl, c.clone()); restoreSets.add(u); noteClearAfterInstall(m, tl, c); continue; }
            if (nulled.contains(tl)) { normal.put(tl, EnumSet.of(St.INST_NULL)); exc.put(tl, c.clone()); noteClearAfterInstall(m, tl, c); continue; }
            EnumSet<St> n = EnumSet.noneOf(St.class), x = EnumSet.noneOf(St.class);
            for (MethodResult r : rs) {
                Summary sm = r == null ? null : r.exits.get(tl);
                if (sm == null) { n.addAll(c); x.addAll(c); continue; }
                n.addAll(apply(sm.normal, c));
                x.addAll(apply(sm.exc, c));
                if (sm.normal.contains(St.CLEARED) || sm.exc.contains(St.CLEARED)) noteClearAfterInstall(m, tl, c);
            }
            normal.put(tl, n);
            exc.put(tl, x);
        }
    }

    /** is `l` the previous value of ℓ: defined by ℓ.get() or by a call to a method that returns ℓ.get()? */
    private boolean fromSavedPrevious(Local l, Unit at, Body b, TL tl) {
        try {
            List<Unit> defs = finder.defs(b).getDefsOfAt(l, at);
            if (defs.isEmpty()) return false;
            for (Unit d : defs) {
                TL.Access ga = finder.accessAt.get(d);
                if (ga != null && ga.kind == TL.AKind.GET && ga.tl == tl) continue;
                if (d instanceof AssignStmt && ((AssignStmt) d).getRightOp() instanceof CastExpr) {
                    Value op = ((CastExpr) ((AssignStmt) d).getRightOp()).getOp();
                    if (op instanceof Local && fromSavedPrevious((Local) op, d, b, tl)) continue;
                    return false;
                }
                if (d instanceof AssignStmt && ((AssignStmt) d).getRightOp() instanceof InvokeExpr) {
                    boolean ok = false;
                    for (SootMethod t : p.appTargets(d)) if (returnsGet.getOrDefault(t, Collections.emptySet()).contains(tl)) ok = true;
                    if (ok) continue;
                }
                return false;
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static EnumSet<St> apply(EnumSet<St> summary, EnumSet<St> cur) {
        EnumSet<St> out = EnumSet.noneOf(St.class);
        for (St s : summary) { if (s == St.PRE) out.addAll(cur); else out.add(s); }
        return out;
    }

    public boolean isRestore(TL.Access a, Body b) {
        if (model.ablRestore) return false;   // ablation: a set whose argument is the previous value is an ordinary install
        Boolean c = restoreCache.get(a.unit);
        if (c != null) return c;
        boolean r = a.arg instanceof Local && fromSavedPrevious((Local) a.arg, a.unit, b, a.tl);
        restoreCache.put(a.unit, r);
        if (r) restoreSets.add(a.unit);
        return r;
    }

    private static final Set<String> MUTATORS = new HashSet<>(Arrays.asList("put", "putAll", "putIfAbsent", "add", "addAll", "push", "offer", "addLast", "addFirst", "computeIfAbsent", "compute", "merge", "append", "write"));

    /** the value installed by a lazy-init set is mutated later in the same method (per-task state hidden in a lazily created container) */
    private boolean mutatedAfter(TL.Access a, Body b) {
        if (!(a.arg instanceof Local)) return false;
        Local v = (Local) a.arg;
        boolean after = false;
        for (Unit u : b.getUnits()) {
            if (u == a.unit) { after = true; continue; }
            if (!after) continue;
            Stmt s = (Stmt) u;
            if (!s.containsInvokeExpr() || !(s.getInvokeExpr() instanceof InstanceInvokeExpr)) continue;
            InstanceInvokeExpr ie = (InstanceInvokeExpr) s.getInvokeExpr();
            if (MUTATORS.contains(ie.getMethodRef().getName()) && reachesFrom(ie.getBase(), v, u, b, 0)) return true;
        }
        return false;
    }

    /** does `x` (possibly) denote v, a copy/cast of v (any definition), or a field loaded from such a local? */
    private boolean reachesFrom(Value x, Local v, Unit at, Body b, int depth) {
        if (x == v) return true;
        if (!(x instanceof Local) || depth > 3) return false;
        try {
            for (Unit d : finder.defs(b).getDefsOfAt((Local) x, at)) {
                if (!(d instanceof AssignStmt)) continue;
                Value rhs = ((AssignStmt) d).getRightOp();
                if (rhs instanceof CastExpr) rhs = ((CastExpr) rhs).getOp();
                if (rhs == v) return true;
                if (rhs instanceof Local && reachesFrom(rhs, v, d, b, depth + 1)) return true;
                if (rhs instanceof InstanceFieldRef && reachesFrom(((InstanceFieldRef) rhs).getBase(), v, d, b, depth + 1)) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /** lazy-init idiom: a get() of ℓ whose result is null-checked by an IfStmt that dominates the set */
    private boolean isLazyInit(TL.Access a, Body b, MHGDominatorsFinder<Unit> dom) {
        if (mutatedAfter(a, b)) return false;
        for (TL.Access o : a.tl.accesses) {
            if (o.method != a.method || o.kind != TL.AKind.GET || !(o.result instanceof Local) || o.unit == a.unit) continue;
            try {
                if (!dom.isDominatedBy(a.unit, o.unit)) continue;
            } catch (Throwable t) {
                continue;
            }
            Local r = (Local) o.result;
            for (Unit u : b.getUnits()) {
                if (!(u instanceof IfStmt)) continue;
                Value c = ((IfStmt) u).getCondition();
                if (!(c instanceof EqExpr || c instanceof NeExpr)) continue;
                BinopExpr be = (BinopExpr) c;
                Value x = be.getOp1(), y = be.getOp2();
                boolean nullCmp = (x instanceof NullConstant && aliasOf(y, r, u, b)) || (y instanceof NullConstant && aliasOf(x, r, u, b));
                if (!nullCmp) continue;
                try {
                    if (dom.isDominatedBy(a.unit, u)) return true;
                } catch (Throwable ignored) {
                }
            }
        }
        return false;
    }

    private boolean aliasOf(Value v, Local r, Unit at, Body b) {
        if (v == r) return true;
        if (!(v instanceof Local)) return false;
        try {
            List<Unit> defs = finder.defs(b).getDefsOfAt((Local) v, at);
            if (defs.isEmpty()) return false;
            for (Unit d : defs) {
                if (!(d instanceof AssignStmt)) return false;
                Value rhs = ((AssignStmt) d).getRightOp();
                if (rhs instanceof CastExpr) rhs = ((CastExpr) rhs).getOp();
                if (rhs != r) return false;
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** the previous value was saved before this install: a get() dominates the set and the method restores somewhere */
    private boolean savedBefore(TL.Access a, Body b, MHGDominatorsFinder<Unit> dom) {
        boolean hasRestore = false;
        for (TL.Access o : a.tl.accesses) if (o.method == a.method && o.kind == TL.AKind.SET && o.unit != a.unit && isRestore(o, b)) hasRestore = true;
        if (!hasRestore) {
            for (Unit u : b.getUnits()) if (restoreSets.contains(u) && !finder.accessAt.containsKey(u)) { hasRestore = true; break; }
        }
        if (!hasRestore) return false;
        for (TL.Access o : a.tl.accesses) {
            if (o.method != a.method || o.kind != TL.AKind.GET || o.result == null || o.unit == a.unit) continue;
            try {
                if (dom.isDominatedBy(a.unit, o.unit)) return true;
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private boolean escapes(ExceptionalUnitGraph g, Body b, Unit u) {
        boolean may;
        if (u instanceof ThrowStmt) may = true;
        else {
            Stmt s = (Stmt) u;
            may = s.containsInvokeExpr() && unitMayThrow(u, s.getInvokeExpr());
        }
        if (!may) return false;
        try {
            RefType exception = RefType.v("java.lang.Exception");
            for (ExceptionalUnitGraph.ExceptionDest d : g.getExceptionDests(u)) {
                if (d.getTrap() != null) continue;
                ThrowableSet ts = d.getThrowables();
                if (ts == null) return true;
                if (ts.catchableAs(exception)) return true;
            }
            return false;
        } catch (Throwable t) {
            return !coveredByCatchAll(b, u);
        }
    }

    public Summary exitsOf(SootMethod m, TL tl) {
        MethodResult r = results.get(m);
        return r == null ? null : r.exits.get(tl);
    }

    public boolean clearsAfterInstall(SootMethod m, TL tl) {
        return clearAfterInstall.getOrDefault(m, Collections.emptySet()).contains(tl);
    }
}
