package tld2;

import soot.*;
import soot.jimple.*;
import soot.toolkits.scalar.LocalDefs;

import java.util.*;

/** Identifies abstract ThreadLocal objects (fields, facades, allocation sites, self-referencing subclasses),
 *  their runtime class, field re-assignments and every access site. */
public final class TLFinder {
    private final Program p;
    private final Model model;
    public final List<TL> tls = new ArrayList<>();
    public final Map<SootField, TL> byField = new HashMap<>();
    public final Map<String, TL> facades = new HashMap<>();
    public final Map<Unit, TL> byAlloc = new HashMap<>();
    /** ThreadLocal subclass -> the TL its `this`-accesses are attributed to */
    public final Map<SootClass, TL> selfOf = new HashMap<>();
    public final Map<Unit, TL.Access> accessAt = new HashMap<>();
    public final List<String> orphanSites = new ArrayList<>();
    public int orphanAccesses = 0;
    private final Map<Body, LocalDefs> defsCache = new HashMap<>();

    public TLFinder(Program p) {
        this.p = p;
        this.model = p.model;
    }

    public LocalDefs defs(Body b) {
        return defsCache.computeIfAbsent(b, bb -> new soot.toolkits.scalar.SimpleLocalDefs(new soot.toolkits.graph.ExceptionalUnitGraph(bb)));
    }

    public boolean isTLClass(SootClass c) {
        Set<String> names = p.supertypeNames(c);
        for (String n : names) if (model.tlLikeClasses.contains(n)) return true;
        return false;
    }

    private boolean isTLClassHeuristic(SootClass c) {
        return c.isPhantom() && c.getName().endsWith("ThreadLocal");
    }

    public boolean isTLType(Type t) {
        if (!(t instanceof RefType)) return false;
        SootClass c = ((RefType) t).getSootClass();
        return isTLClass(c) || isTLClassHeuristic(c);
    }

    public void run() {
        // 1. fields
        for (SootClass c : p.appClasses) {
            for (SootField f : new ArrayList<>(c.getFields())) {
                if (!isTLType(f.getType())) continue;
                TL tl = new TL(f.getSignature(), TL.Kind.FIELD, f, c, f.isStatic());
                tl.tlLikeHeuristic = !isTLClass(((RefType) f.getType()).getSootClass());
                tls.add(tl);
                byField.put(f, tl);
            }
        }
        // 2. assignments to TL fields (runtime class, re-assignment) and allocation-site TLs
        Set<Unit> fieldAllocs = new HashSet<>();
        for (Map.Entry<SootMethod, Body> e : p.bodies.entrySet()) {
            SootMethod m = e.getKey();
            Body b = e.getValue();
            for (Unit u : b.getUnits()) {
                if (!(u instanceof AssignStmt)) continue;
                AssignStmt as = (AssignStmt) u;
                if (!(as.getLeftOp() instanceof FieldRef)) continue;
                SootField f = fieldOf((FieldRef) as.getLeftOp());
                TL tl = f == null ? null : byField.get(f);
                if (tl == null) continue;
                if (!m.getName().equals("<init>") && !m.getName().equals("<clinit>")) tl.reassignedIn.add(m);
                if (as.getRightOp() instanceof Local) describeAllocation(tl, (Local) as.getRightOp(), u, b, fieldAllocs);
            }
        }
        for (Map.Entry<SootMethod, Body> e : p.bodies.entrySet()) {
            SootMethod m = e.getKey();
            Body b = e.getValue();
            for (Unit u : b.getUnits()) {
                if (!(u instanceof AssignStmt) || !(((AssignStmt) u).getRightOp() instanceof NewExpr)) continue;
                if (fieldAllocs.contains(u)) continue;
                SootClass nc = ((NewExpr) ((AssignStmt) u).getRightOp()).getBaseType().getSootClass();
                if (!(isTLClass(nc) || isTLClassHeuristic(nc))) continue;
                // is the new object stored to a TL field later in this body (through a different local)? then it is a field TL
                if (storedToTLField((Local) ((AssignStmt) u).getLeftOp(), u, b)) continue;
                TL tl = new TL("alloc:" + m.getSignature() + "@" + Program.line(u), TL.Kind.ALLOC, null, m.getDeclaringClass(), false);
                tl.allocMethod = m;
                tl.allocUnit = u;
                tl.runtimeClass = nc;
                tls.add(tl);
                byAlloc.put(u, tl);
            }
        }
        for (TL tl : tls) finishDecl(tl);
        // 3. self-accesses inside ThreadLocal subclasses: attribute to the unique field TL whose runtime/declared class is R
        Map<SootClass, List<TL>> byRuntime = new HashMap<>();
        for (TL tl : tls) {
            if (tl.kind != TL.Kind.FIELD) continue;
            SootClass r = tl.runtimeClass != null && !tl.withInitial ? tl.runtimeClass : ((RefType) tl.field.getType()).getSootClass();
            if (r.isApplicationClass() && isTLClass(r)) byRuntime.computeIfAbsent(r, k -> new ArrayList<>()).add(tl);
        }
        for (SootClass c : p.appClasses) {
            if (!isTLClass(c) || model.tlLikeClasses.contains(c.getName())) continue;
            List<TL> owners = byRuntime.get(c);
            if (owners != null && owners.size() == 1) selfOf.put(c, owners.get(0));
        }
        // 4. accesses
        for (Map.Entry<SootMethod, Body> e : p.bodies.entrySet()) {
            SootMethod m = e.getKey();
            Body b = e.getValue();
            for (Unit u : b.getUnits()) {
                Stmt s = (Stmt) u;
                if (!s.containsInvokeExpr()) continue;
                InvokeExpr ie = s.getInvokeExpr();
                SootClass dc = ie.getMethodRef().getDeclaringClass();
                String name = ie.getMethodRef().getName();
                if (ie instanceof StaticInvokeExpr) {
                    String[][] fac = model.facades.get(dc.getName());
                    if (fac == null) continue;
                    TL.AKind k = null;
                    if (Arrays.asList(fac[0]).contains(name)) k = TL.AKind.SET;
                    else if (Arrays.asList(fac[1]).contains(name)) k = TL.AKind.REMOVE;
                    if (k == null) continue;
                    TL tl = facades.computeIfAbsent(dc.getName(), n -> {
                        TL t = new TL("facade:" + n, TL.Kind.FACADE, null, dc, true);
                        t.facadeClass = n;
                        t.loader = "JDK";
                        tls.add(t);
                        return t;
                    });
                    add(new TL.Access(tl, m, u, k, null, null));
                    continue;
                }
                if (!(ie instanceof InstanceInvokeExpr)) continue;
                if (!(isTLClass(dc) || isTLClassHeuristic(dc))) continue;
                TL.AKind k;
                switch (name) {
                    case "set": k = TL.AKind.SET; break;
                    case "get": k = TL.AKind.GET; break;
                    case "remove": case "close": k = TL.AKind.REMOVE; break;
                    default: continue;
                }
                if (ie.getArgCount() > (k == TL.AKind.SET ? 1 : 0)) continue;   // not the ThreadLocal API shape
                Local base = (Local) ((InstanceInvokeExpr) ie).getBase();
                TL tl = resolveBase(base, u, b, 0);
                if (tl == null) {
                    // `this.set(..)` / `super.get()` inside a ThreadLocal subclass
                    if (isThis(base, b) && isTLClass(m.getDeclaringClass())) {
                        tl = selfOf.get(m.getDeclaringClass());
                        if (tl == null) tl = selfTL(m.getDeclaringClass());
                    }
                }
                if (tl == null) {
                    orphanAccesses++;
                    if (orphanSites.size() < 50) orphanSites.add(m.getSignature() + " L" + Program.line(u) + ": " + u);
                    continue;
                }
                Value arg = ie.getArgCount() > 0 ? ie.getArg(0) : null;
                if (k == TL.AKind.SET && arg instanceof NullConstant) k = TL.AKind.SET_NULL;
                Value res = (s instanceof AssignStmt) ? ((AssignStmt) s).getLeftOp() : null;
                add(new TL.Access(tl, m, u, k, arg, res));
            }
        }
    }

    private TL selfTL(SootClass c) {
        TL t = selfOf.get(c);
        if (t != null) return t;
        boolean hasStaticSelf = false;
        for (SootField f : c.getFields()) if (f.isStatic() && f.getType() instanceof RefType && ((RefType) f.getType()).getSootClass().equals(c)) hasStaticSelf = true;
        t = new TL("self:" + c.getName(), TL.Kind.SELF, null, c, hasStaticSelf);
        t.runtimeClass = c;
        t.keyApp = !model.isJdk(c.getName());
        Set<String> names = p.supertypeNames(c);
        t.inheritable = names.contains("java.lang.InheritableThreadLocal") || names.contains("com.alibaba.ttl.TransmittableThreadLocal");
        if (c.declaresMethodByName("initialValue")) t.lazyInit = true;
        tls.add(t);
        selfOf.put(c, t);
        return t;
    }

    private boolean isThis(Local l, Body b) {
        try {
            for (Unit d : defs(b).getDefsOfAt(l, b.getUnits().getFirst())) {
                if (d instanceof IdentityStmt && ((IdentityStmt) d).getRightOp() instanceof ThisRef) return true;
            }
        } catch (Throwable ignored) {
        }
        for (Unit u : b.getUnits()) {
            if (u instanceof IdentityStmt && ((IdentityStmt) u).getLeftOp() == l && ((IdentityStmt) u).getRightOp() instanceof ThisRef) return true;
        }
        return false;
    }

    private boolean storedToTLField(Local l, Unit from, Body b) {
        for (Unit u : b.getUnits()) {
            if (!(u instanceof AssignStmt)) continue;
            AssignStmt as = (AssignStmt) u;
            if (as.getLeftOp() instanceof FieldRef && as.getRightOp() instanceof Local) {
                SootField f = fieldOf((FieldRef) as.getLeftOp());
                if (f != null && byField.containsKey(f)) {
                    try {
                        for (Unit d : defs(b).getDefsOfAt((Local) as.getRightOp(), u)) if (d == from) return true;
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        return false;
    }

    private void add(TL.Access a) {
        a.tl.accesses.add(a);
        accessAt.put(a.unit, a);
    }

    private SootField fieldOf(FieldRef fr) {
        try {
            return fr.getField();
        } catch (Throwable t) {
            return null;
        }
    }

    /** base local of ℓ.set/get/remove -> the TL it denotes (field load, allocation site, cast, one level of accessor call) */
    private TL resolveBase(Local base, Unit at, Body b, int depth) {
        try {
            for (Unit d : defs(b).getDefsOfAt(base, at)) {
                if (!(d instanceof AssignStmt)) continue;
                Value rhs = ((AssignStmt) d).getRightOp();
                if (rhs instanceof CastExpr && ((CastExpr) rhs).getOp() instanceof Local)
                    return resolveBase((Local) ((CastExpr) rhs).getOp(), d, b, depth);
                if (rhs instanceof FieldRef) {
                    SootField f = fieldOf((FieldRef) rhs);
                    if (f != null && byField.containsKey(f)) return byField.get(f);
                    return null;
                }
                if (rhs instanceof NewExpr) return byAlloc.get(d);
                if (rhs instanceof Local) return resolveBase((Local) rhs, d, b, depth);
                if (rhs instanceof InvokeExpr && depth < 1) {
                    for (SootMethod t : p.appTargets(d)) {
                        Body tb = p.bodies.get(t);
                        if (tb == null) continue;
                        for (Unit ru : tb.getUnits()) {
                            if (ru instanceof ReturnStmt && ((ReturnStmt) ru).getOp() instanceof Local) {
                                TL r = resolveBase((Local) ((ReturnStmt) ru).getOp(), ru, tb, depth + 1);
                                if (r != null) return r;
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private void describeAllocation(TL tl, Local rhs, Unit at, Body b, Set<Unit> fieldAllocs) {
        try {
            for (Unit d : defs(b).getDefsOfAt(rhs, at)) {
                if (!(d instanceof AssignStmt)) continue;
                Value v = ((AssignStmt) d).getRightOp();
                if (v instanceof NewExpr) {
                    tl.runtimeClass = ((NewExpr) v).getBaseType().getSootClass();
                    fieldAllocs.add(d);
                } else if (v instanceof StaticInvokeExpr && ((StaticInvokeExpr) v).getMethodRef().getName().equals("withInitial")) {
                    tl.withInitial = true;
                    tl.lazyInit = true;
                    if (((StaticInvokeExpr) v).getArgCount() == 1 && ((StaticInvokeExpr) v).getArg(0) instanceof Local)
                        describeSupplier(tl, (Local) ((StaticInvokeExpr) v).getArg(0), d, b);
                } else if (v instanceof CastExpr && ((CastExpr) v).getOp() instanceof Local) {
                    describeAllocation(tl, (Local) ((CastExpr) v).getOp(), d, b, fieldAllocs);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private void describeSupplier(TL tl, Local sup, Unit at, Body b) {
        for (Unit d : defs(b).getDefsOfAt(sup, at)) {
            if (!(d instanceof AssignStmt)) continue;
            Value v = ((AssignStmt) d).getRightOp();
            if (v instanceof DynamicInvokeExpr) {
                tl.lambdaCaptured = ((DynamicInvokeExpr) v).getArgCount();
                for (Value ba : ((DynamicInvokeExpr) v).getBootstrapArgs()) {
                    if (ba instanceof MethodHandle) {
                        SootMethodRef ref = ((MethodHandle) ba).getMethodRef();
                        if (ref != null) tl.supplierImpl = ref;
                    }
                }
            } else if (v instanceof StaticInvokeExpr) {
                StaticInvokeExpr sie = (StaticInvokeExpr) v;
                tl.lambdaCaptured = sie.getArgCount();
                tl.runtimeClass = sie.getMethodRef().getDeclaringClass();
            } else if (v instanceof NewExpr) {
                tl.runtimeClass = ((NewExpr) v).getBaseType().getSootClass();
            }
        }
    }

    private void finishDecl(TL tl) {
        SootClass declared;
        if (tl.kind == TL.Kind.FIELD) declared = ((RefType) tl.field.getType()).getSootClass();
        else if (tl.kind == TL.Kind.ALLOC) declared = tl.runtimeClass;
        else return;
        SootClass r = tl.runtimeClass != null && !tl.withInitial ? tl.runtimeClass : declared;
        Set<String> names = p.supertypeNames(r);
        tl.inheritable = names.contains("java.lang.InheritableThreadLocal") || names.contains("com.alibaba.ttl.TransmittableThreadLocal");
        if (tl.runtimeClass != null && !tl.withInitial) {
            SootClass rc = tl.runtimeClass;
            tl.keyApp = !model.isJdk(rc.getName());
            if (rc.isApplicationClass()) {
                for (SootField f : rc.getFields()) if (f.getName().startsWith("this$")) tl.outerCapture = true;
                if (rc.declaresMethodByName("initialValue")) tl.lazyInit = true;
            }
        }
        if (tl.lambdaCaptured > 0) tl.outerCapture = true;
        if (tl.runtimeClass == null && !tl.withInitial && !model.isJdk(declared.getName())) tl.keyApp = true;
    }
}
