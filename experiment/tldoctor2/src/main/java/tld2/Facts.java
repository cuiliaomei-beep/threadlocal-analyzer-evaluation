package tld2;

import soot.*;
import soot.jimple.*;

import java.util.*;

/** Layer-1 facts (FSE-PLAN §3.2): Decl (host lifetime, capture), Val (loader, growth), Ctx (thread kinds). */
public final class Facts {
    private final Program p;
    private final TLFinder finder;
    private final Model model;

    public Facts(Program p, TLFinder finder) {
        this.p = p; this.finder = finder; this.model = p.model;
    }

    public void run() {
        for (TL tl : finder.tls) {
            if (tl.kind == TL.Kind.FIELD) {
                host(tl);
                value(tl);
            } else if (tl.kind == TL.Kind.ALLOC) {
                String an = tl.allocMethod.getName();
                if (an.equals("<clinit>")) { tl.host = "LONGLIVED"; tl.hostReason = "allocated-in-clinit"; }
                else if (an.equals("<init>")) { host(tl); tl.hostReason = "allocated-in-constructor;" + tl.hostReason; }
                else { tl.host = "CHURN"; tl.hostReason = "allocated-per-call:" + an; }
                value(tl);
            } else if (tl.kind == TL.Kind.SELF) {
                tl.host = tl.isStatic ? "LONGLIVED" : "UNKNOWN";
                tl.hostReason = tl.isStatic ? "static-self-instance" : "threadlocal-subclass";
                value(tl);
            } else {
                tl.host = "LONGLIVED";
                tl.hostReason = "facade";
            }
            if (model.ablHost && tl.kind != TL.Kind.FACADE && !tl.isStatic && !"allocated-in-clinit".equals(tl.hostReason)) {
                tl.host = "UNKNOWN"; tl.hostReason = "ablation:host";
            }
            if (model.ablValue && tl.kind != TL.Kind.FACADE) declaredValue(tl);
            if (model.ablCtx) { tl.ctx.add("UNKNOWN"); }
            else context(tl);
        }
    }

    // ---------- ablation: value facts from the declared type only ----------
    /** replaces the result of value(): the value type is the type argument of the declaration, as a rule on declarations sees it */
    private void declaredValue(TL tl) {
        String sig = null;
        if (tl.field != null) {
            soot.tagkit.Tag t = tl.field.getTag("SignatureTag");
            if (t instanceof soot.tagkit.SignatureTag) sig = ((soot.tagkit.SignatureTag) t).getSignature();
        }
        String arg = firstTypeArgument(sig);
        if (arg == null && tl.runtimeClass != null && tl.runtimeClass.isApplicationClass()) {
            soot.tagkit.Tag t = tl.runtimeClass.getTag("SignatureTag");
            if (t instanceof soot.tagkit.SignatureTag) {
                String cs = ((soot.tagkit.SignatureTag) t).getSignature();
                // class signature: optional formal type parameters, then the superclass with its type arguments
                int start = 0;
                if (cs.startsWith("<")) { int d = 0; for (int i = 0; i < cs.length(); i++) { char c = cs.charAt(i); if (c == '<') d++; if (c == '>') { d--; if (d == 0) { start = i + 1; break; } } } }
                arg = firstTypeArgument(cs.substring(start));
            }
        }
        tl.valueTypes.clear();
        tl.softWrapped = false; tl.growable = false; tl.bufferValue = false; tl.valueUnknownFactory = false;
        if (arg != null && (arg.startsWith("java.lang.ref.SoftReference<") || arg.startsWith("java.lang.ref.WeakReference<"))) {
            tl.softWrapped = true;
            arg = firstTypeArgument("L" + arg.replace('.', '/') );
        }
        if (arg == null) { tl.valueTypes.add("?"); tl.loader = "UNKNOWN"; return; }
        String raw = arg.contains("<") ? arg.substring(0, arg.indexOf('<')) : arg;
        tl.valueTypes.add(raw);
        String cls = raw.endsWith("[]") ? raw.substring(0, raw.indexOf('[')) : raw;
        if (cls.equals("java.lang.Object") || cls.equals("?")) { tl.loader = "UNKNOWN"; return; }
        if (model.isGrowableType(cls) && !tl.softWrapped) tl.growable = true;
        if (model.isBufferType(cls)) tl.bufferValue = true;
        tl.loader = cls.equals("prim") || model.isJdk(cls) ? "JDK" : "APP";
    }

    /** first type argument of a generic type signature, as a dotted name that keeps its own type arguments; null if there is none */
    private static String firstTypeArgument(String sig) {
        if (sig == null) return null;
        int lt = sig.indexOf('<');
        if (lt < 0) return null;
        int i = lt + 1;
        if (i < sig.length() && (sig.charAt(i) == '+' || sig.charAt(i) == '-')) i++;
        if (i >= sig.length()) return null;
        char c = sig.charAt(i);
        if (c == '*' || c == 'T') return "?";
        int dims = 0;
        while (i < sig.length() && sig.charAt(i) == '[') { dims++; i++; }
        if (i >= sig.length()) return null;
        String base;
        if (sig.charAt(i) != 'L') base = "prim";
        else {
            int d = 0, j = i + 1;
            for (; j < sig.length(); j++) {
                char x = sig.charAt(j);
                if (x == '<') d++;
                else if (x == '>') d--;
                else if (x == ';' && d == 0) break;
            }
            base = sig.substring(i + 1, Math.min(j, sig.length())).replace('/', '.');
        }
        StringBuilder sb = new StringBuilder(base);
        for (int k = 0; k < dims; k++) sb.append("[]");
        return sb.toString();
    }

    // ---------- Decl: host lifetime ----------
    private void host(TL tl) {
        if (tl.isStatic) { tl.host = "LONGLIVED"; tl.hostReason = "static"; return; }
        SootClass h = tl.declClass;
        String simple = h.getShortName();
        Set<String> supers = p.supertypeNames(h);
        List<SootMethod> sites = p.newSites.getOrDefault(h, Collections.emptyList());
        boolean singletonAnn = false;
        for (String a : Program.annotationTypes(h)) for (String pfx : model.singletonAnnotations) if (a.startsWith(pfx)) singletonAnn = true;
        boolean selfStatic = false;
        for (SootField f : h.getFields()) if (f.isStatic() && f.getType() instanceof RefType && ((RefType) f.getType()).getSootClass().equals(h)) selfStatic = true;
        boolean closeable = supers.contains("java.io.Closeable") || supers.contains("java.lang.AutoCloseable");
        boolean hasEnd = false;
        for (SootMethod m : h.getMethods()) if (model.lifecycleEndNames.matcher(m.getName()).matches() && !m.isStatic()) hasEnd = true;
        boolean churnName = false, longName = false;
        for (String x : model.churnHostHints) if (simple.endsWith(x) || simple.contains(x)) churnName = true;
        for (String x : model.longLivedHostHints) if (simple.endsWith(x)) longName = true;
        // instantiation sites: outside the class (and its inner classes) vs. its own static factories
        Set<SootMethod> external = new HashSet<>(), factory = new HashSet<>();
        String outer = h.getName().split("\\$")[0];
        for (SootMethod s : sites) {
            if (s.getDeclaringClass().getName().split("\\$")[0].equals(outer)) { if (s.isStatic()) factory.add(s); }
            else external.add(s);
        }
        String siteInfo = "external-sites=" + external.size() + ";factory-sites=" + factory.size();
        if (singletonAnn || selfStatic) { tl.host = "LONGLIVED"; tl.hostReason = (singletonAnn ? "singleton-annotation;" : "static-self-instance;") + siteInfo; return; }
        if (longName && external.size() < 2) { tl.host = "LONGLIVED"; tl.hostReason = "long-lived-name;" + siteInfo; return; }
        if ((closeable || churnName || hasEnd || external.size() >= 2) && (!external.isEmpty() || !factory.isEmpty())) {
            tl.host = "CHURN";
            tl.hostReason = (closeable ? "closeable;" : "") + (hasEnd ? "has-end-method;" : "") + (churnName ? "churn-name;" : "") + siteInfo;
            return;
        }
        if (longName) { tl.host = "LONGLIVED"; tl.hostReason = "long-lived-name;" + siteInfo; return; }
        if (sites.isEmpty()) { tl.host = "UNKNOWN"; tl.hostReason = "not-instantiated-in-jar"; return; }
        tl.host = "UNKNOWN";
        tl.hostReason = siteInfo;
    }

    // ---------- Val: loader / growth ----------
    private final Set<Unit> chaseSeen = new HashSet<>();

    private void value(TL tl) {
        chaseSeen.clear();
        Set<String> types = new TreeSet<>();
        for (TL.Access a : tl.accesses) {
            if (a.kind != TL.AKind.SET || a.arg == null) continue;
            Body b = p.bodies.get(a.method);
            if (b != null) chase(a.arg, a.unit, b, 0, tl, types);
        }
        if (tl.runtimeClass != null && tl.runtimeClass.isApplicationClass()) {
            for (SootMethod m : tl.runtimeClass.getMethods()) {
                // initialValue() override, the Supplier of withInitial, or a get() override that lazily creates the value
                if ((m.getName().equals("initialValue") || m.getName().equals("get")) && !m.isStatic() && m.getParameterCount() == 0 && p.bodies.containsKey(m))
                    chaseReturns(m, 0, tl, types);
            }
        }
        if (tl.supplierImpl != null) {
            try {
                SootMethod im = tl.supplierImpl.tryResolve();
                if (im != null) {
                    if (im.getName().equals("<init>")) types.add(im.getDeclaringClass().getName());
                    else if (p.bodies.containsKey(im)) chaseReturns(im, 0, tl, types);
                    else types.add(typeName(im.getReturnType()));
                }
            } catch (Throwable ignored) {
            }
        }
        // contents stored into a JDK container / array obtained from ℓ.get(): m.put(k, v), c.add(v), a[i] = v
        Set<String> contentTypes = new TreeSet<>();
        Set<String> direct = new TreeSet<>(types);
        for (TL.Access a : tl.accesses) {
            if (a.kind != TL.AKind.GET || !(a.result instanceof Local)) continue;
            Body b = p.bodies.get(a.method);
            if (b == null) continue;
            Local r = (Local) a.result;
            for (Unit u : b.getUnits()) {
                Stmt s = (Stmt) u;
                if (s instanceof AssignStmt && ((AssignStmt) s).getLeftOp() instanceof ArrayRef) {
                    ArrayRef ar = (ArrayRef) ((AssignStmt) s).getLeftOp();
                    if (aliasOf(ar.getBase(), r, u, b)) { chase(((AssignStmt) s).getRightOp(), u, b, 1, tl, contentTypes); tl.contentChased = true; }
                    continue;
                }
                if (!s.containsInvokeExpr() || !(s.getInvokeExpr() instanceof InstanceInvokeExpr)) continue;
                InstanceInvokeExpr ie = (InstanceInvokeExpr) s.getInvokeExpr();
                if (!aliasOf(ie.getBase(), r, u, b)) continue;
                String n = ie.getMethodRef().getName();
                if ((n.equals("clear") || n.equals("reset") || n.equals("removeAll")) && ie.getArgCount() == 0) tl.contentCleared = true;
                if (n.equals("setLength") && ie.getArgCount() == 1 && ie.getArg(0) instanceof IntConstant && ((IntConstant) ie.getArg(0)).value == 0) tl.contentCleared = true;
                Value v = null;
                if ((n.equals("put") || n.equals("putIfAbsent") || n.equals("set") || n.equals("replace") || n.equals("computeIfAbsent") || n.equals("compute") || n.equals("merge")) && ie.getArgCount() >= 2) v = ie.getArg(ie.getArgCount() - 1);
                else if ((n.equals("add") || n.equals("offer") || n.equals("push") || n.equals("addLast") || n.equals("addFirst") || n.equals("addElement")) && ie.getArgCount() >= 1) v = ie.getArg(ie.getArgCount() - 1);
                if (v != null) { chase(v, u, b, 1, tl, contentTypes); tl.contentChased = true; }
            }
        }
        // contents cleared per use (list.clear(), sb.setLength(0)) do not linger: they count for growth, not for the loader
        types.addAll(contentTypes);
        tl.valueTypes.addAll(types);
        Set<String> loaderTypes = types;   // cleared contents still linger until the clear runs (H0128: never on the right thread)
        boolean app = false, unknown = tl.valueUnknownFactory;
        for (String t : types) {
            if (t.equals("?")) continue;
            String cls = t.endsWith("[]") ? t.substring(0, t.indexOf('[')) : t;
            if (model.isGrowableType(cls)) tl.growable = true;
            if (model.isBufferType(cls)) tl.bufferValue = true;
        }
        for (String t : loaderTypes) {
            if (t.equals("?")) { unknown = true; continue; }
            String cls = t.endsWith("[]") ? t.substring(0, t.indexOf('[')) : t;
            if (cls.equals("prim") || cls.equals("java.lang.Object")) continue;
            if (!model.isJdk(cls)) app = true;
        }
        if (loaderTypes.contains("java.lang.Object") && loaderTypes.size() == 1) unknown = true;
        if (loaderTypes.isEmpty() && !types.isEmpty()) unknown = true;
        tl.loader = app ? "APP" : (unknown ? "UNKNOWN" : (types.isEmpty() ? "UNKNOWN" : "JDK"));
        if (tl.softWrapped) tl.growable = false;
    }

    private void chaseReturns(SootMethod m, int depth, TL tl, Set<String> types) {
        Body b = p.bodies.get(m);
        if (b == null || depth > model.valueChaseDepth) { types.add(typeName(m.getReturnType())); return; }
        boolean any = false;
        for (Unit u : b.getUnits()) {
            if (u instanceof ReturnStmt) {
                any = true;
                chase(((ReturnStmt) u).getOp(), u, b, depth + 1, tl, types);
            }
        }
        if (!any) types.add(typeName(m.getReturnType()));
    }

    private static final boolean DEBUG = System.getenv("TLD_DEBUG") != null;

    private void chase(Value v, Unit at, Body b, int depth, TL tl, Set<String> types) {
        if (DEBUG) System.err.println("  chase d=" + depth + " " + v + " @ " + at + " in " + b.getMethod().getSignature());
        if (depth > model.valueChaseDepth + 2) { types.add(typeName(v.getType())); return; }
        if (v instanceof NullConstant) return;
        if (v instanceof Constant) { types.add(typeName(v.getType())); return; }
        if (!(v instanceof Local)) { types.add(typeName(v.getType())); return; }
        Local l = (Local) v;
        List<Unit> defs;
        try {
            defs = finder.defs(b).getDefsOfAt(l, at);
        } catch (Throwable t) {
            types.add(typeName(l.getType()));
            return;
        }
        if (defs.isEmpty()) { types.add(typeName(l.getType())); return; }
        for (Unit d : defs) {
            if (!chaseSeen.add(d)) continue;   // each definition is chased once per ThreadLocal (bounds fan-out)
            if (d instanceof IdentityStmt) {
                Value rv = ((IdentityStmt) d).getRightOp();
                if (rv instanceof ParameterRef && depth < model.valueChaseDepth) {
                    // follow the parameter back to the arguments at (app) call sites, bounded
                    int idx = ((ParameterRef) rv).getIndex();
                    SootMethod m = b.getMethod();
                    Set<SootMethod> cs = p.callersOf(m);
                    int n = 0;
                    if (cs.isEmpty()) types.add(typeName(l.getType()));
                    for (SootMethod c : cs) {
                        if (++n > 12) { types.add(typeName(l.getType())); break; }
                        Body cb = p.bodies.get(c);
                        if (cb == null) continue;
                        for (Unit cu : cb.getUnits()) {
                            Stmt cs2 = (Stmt) cu;
                            if (!cs2.containsInvokeExpr()) continue;
                            Set<SootMethod> ts = p.targets.getOrDefault(cu, Collections.emptySet());
                            if (!ts.contains(m)) continue;
                            InvokeExpr ie = cs2.getInvokeExpr();
                            if (idx < ie.getArgCount()) chase(ie.getArg(idx), cu, cb, depth + 1, tl, types);
                        }
                    }
                } else types.add(typeName(l.getType()));
                continue;
            }
            if (!(d instanceof AssignStmt)) { types.add(typeName(l.getType())); continue; }
            Value rhs = ((AssignStmt) d).getRightOp();
            if (DEBUG) System.err.println("    def " + rhs.getClass().getSimpleName() + ": " + d);
            if (rhs instanceof NewExpr) {
                String n = ((NewExpr) rhs).getBaseType().getClassName();
                if (n.equals("java.lang.ref.SoftReference") || n.equals("java.lang.ref.WeakReference")) {
                    tl.softWrapped = true;
                    Value inner = constructorArg(b, l, d);
                    if (inner != null) chase(inner, d, b, depth + 1, tl, types); else types.add("?");
                } else types.add(n);
            } else if (rhs instanceof NewArrayExpr) {
                types.add(typeName(((NewArrayExpr) rhs).getBaseType()) + "[]");
            } else if (rhs instanceof NewMultiArrayExpr) {
                types.add(typeName(((NewMultiArrayExpr) rhs).getBaseType().baseType) + "[]");
            } else if (rhs instanceof CastExpr) {
                chase(((CastExpr) rhs).getOp(), d, b, depth, tl, types);
            } else if (rhs instanceof Local) {
                chase(rhs, d, b, depth, tl, types);
            } else if (rhs instanceof DynamicInvokeExpr) {
                // raw invokedynamic (LambdaMetafactory not desugared by Soot): the implementation handle tells what the lambda produces
                boolean any = false;
                for (Value ba : ((DynamicInvokeExpr) rhs).getBootstrapArgs()) {
                    if (!(ba instanceof MethodHandle)) continue;
                    SootMethodRef ref = ((MethodHandle) ba).getMethodRef();
                    if (ref == null) continue;
                    any = true;
                    if (ref.getName().equals("<init>")) { types.add(ref.getDeclaringClass().getName()); continue; }
                    SootMethod im = null;
                    try { im = ref.tryResolve(); } catch (Throwable ignored) { }
                    if (im != null && p.bodies.containsKey(im) && depth < model.valueChaseDepth + 2) chaseReturns(im, depth + 1, tl, types);
                    else types.add(typeName(ref.getReturnType()));
                }
                if (!any) types.add(typeName(rhs.getType()));
            } else if (rhs instanceof InvokeExpr) {
                InvokeExpr ie = (InvokeExpr) rhs;
                String dc = ie.getMethodRef().getDeclaringClass().getName();
                String mn = ie.getMethodRef().getName();
                TL.Access ga = finder.accessAt.get(d);
                if (ga != null && ga.kind == TL.AKind.GET) { types.add(typeName(l.getType())); continue; }
                if (mn.equals("bootstrap$") && dc.contains("$lambda")) {
                    // Soot LambdaMetaFactory synthetic class: the value produced by the lambda is what its functional method returns
                    SootClass lc = ie.getMethodRef().getDeclaringClass();
                    boolean any = false;
                    for (SootMethod fm : lc.getMethods()) {
                        if (fm.isStatic() || fm.isConstructor() || !p.bodies.containsKey(fm) || fm.getReturnType() instanceof VoidType) continue;
                        chaseReturns(fm, depth + 1, tl, types);
                        any = true;
                    }
                    if (!any) types.add(typeName(ie.getMethodRef().getReturnType()));
                    continue;
                }
                // transparent JDK wrappers: the value flows through Optional / Objects.requireNonNull
                if (dc.equals("java.util.Optional")) {
                    if (mn.equals("of") || mn.equals("ofNullable")) { chase(ie.getArg(0), d, b, depth + 1, tl, types); continue; }
                    if (mn.equals("orElseGet") || mn.equals("orElse")) {
                        chase(ie.getArg(0), d, b, depth + 1, tl, types);
                        if (ie instanceof InstanceInvokeExpr) chase(((InstanceInvokeExpr) ie).getBase(), d, b, depth + 1, tl, types);
                        continue;
                    }
                    if ((mn.equals("get") || mn.equals("orElseThrow")) && ie instanceof InstanceInvokeExpr) { chase(((InstanceInvokeExpr) ie).getBase(), d, b, depth + 1, tl, types); continue; }
                }
                if (dc.equals("java.util.Objects") && mn.startsWith("requireNonNull") && ie.getArgCount() >= 1) { chase(ie.getArg(0), d, b, depth + 1, tl, types); continue; }
                if (model.isUnknownFactory(dc, mn)) { tl.valueUnknownFactory = true; types.add("?"); continue; }
                Set<SootMethod> ts = p.appTargets(d);
                if (!ts.isEmpty() && depth < model.valueChaseDepth) {
                    for (SootMethod t : ts) chaseReturns(t, depth + 1, tl, types);
                } else {
                    types.add(typeName(ie.getMethodRef().getReturnType()));
                }
            } else if (rhs instanceof FieldRef) {
                types.add(typeName(((FieldRef) rhs).getFieldRef().type()));
            } else if (rhs instanceof ArrayRef) {
                types.add(typeName(rhs.getType()));
            } else {
                types.add(typeName(rhs.getType()));
            }
        }
    }

    /** is `v` the local `r` itself, or a cast/copy of it? */
    private boolean aliasOf(Value v, Local r, Unit at, Body b) {
        if (v == r) return true;
        if (!(v instanceof Local)) return false;
        try {
            for (Unit d : finder.defs(b).getDefsOfAt((Local) v, at)) {
                if (!(d instanceof AssignStmt)) return false;
                Value rhs = ((AssignStmt) d).getRightOp();
                if (rhs instanceof CastExpr) rhs = ((CastExpr) rhs).getOp();
                if (rhs != r) return false;
            }
            return !finder.defs(b).getDefsOfAt((Local) v, at).isEmpty();
        } catch (Throwable t) {
            return false;
        }
    }

    private Value constructorArg(Body b, Local l, Unit newUnit) {
        Unit u = b.getUnits().getSuccOf(newUnit);
        int guard = 0;
        while (u != null && guard++ < 50) {
            Stmt s = (Stmt) u;
            if (s.containsInvokeExpr() && s.getInvokeExpr() instanceof SpecialInvokeExpr) {
                SpecialInvokeExpr sie = (SpecialInvokeExpr) s.getInvokeExpr();
                if (sie.getBase() == l && sie.getMethodRef().getName().equals("<init>") && sie.getArgCount() >= 1) return sie.getArg(0);
            }
            u = b.getUnits().getSuccOf(u);
        }
        return null;
    }

    private static String typeName(Type t) {
        if (t instanceof RefType) return ((RefType) t).getClassName();
        if (t instanceof ArrayType) return typeName(((ArrayType) t).baseType) + "[]";
        return "prim";
    }

    // ---------- Ctx: thread kinds reaching the access sites ----------
    private void context(TL tl) {
        Set<SootMethod> start = tl.accessMethods();
        Deque<SootMethod> work = new ArrayDeque<>();
        Map<SootMethod, Integer> depth = new HashMap<>();
        for (SootMethod m : start) { work.add(m); depth.put(m, 0); }
        int visited = 0;
        boolean publicApi = false;   // a public method of a non-test class was traversed: library users may call it from any thread
        while (!work.isEmpty()) {
            SootMethod m = work.poll();
            if (++visited > model.ctxMaxVisited) { tl.ctx.add("UNKNOWN"); break; }
            Set<String> kinds = classify(m);
            if ((m.isPublic() || m.isProtected()) && !m.getName().startsWith("<") && !model.isTestClass(m.getDeclaringClass().getName()) && !kinds.contains("SHORTLIVED")) publicApi = true;
            if (!kinds.isEmpty()) {
                tl.ctx.addAll(kinds);
                if (tl.entryMethods.size() < 8) tl.entryMethods.add(kinds + " " + m.getSignature());
                continue;
            }
            int d = depth.get(m);
            Set<SootMethod> cs = p.callersOf(m);
            if (cs.isEmpty()) {
                if ((m.isPublic() || m.isProtected()) && !m.getName().equals("<clinit>")) tl.ctx.add("UNKNOWN");
                continue;
            }
            if (d >= model.ctxMaxDepth) { tl.ctx.add("UNKNOWN"); continue; }
            for (SootMethod c : cs) if (!depth.containsKey(c)) { depth.put(c, d + 1); work.add(c); }
        }
        if (tl.ctx.isEmpty() || (tl.ctx.equals(Collections.singleton("SHORTLIVED")) && publicApi)) tl.ctx.add("UNKNOWN");
    }

    public Set<String> classify(SootMethod m) {
        Set<String> out = new TreeSet<>();
        SootClass c = m.getDeclaringClass();
        if (model.isTestClass(c.getName())) { out.add("SHORTLIVED"); return out; }
        List<String> anns = new ArrayList<>(Program.annotationTypes(m));
        anns.addAll(Program.annotationTypes(c));
        Set<String> supers = p.supertypeNames(c);
        supers.remove(c.getName());
        for (Model.EntryPattern ep : model.entryPatterns) {
            boolean hit = false;
            if (ep.mainMethod && m.getName().equals("main") && m.isStatic()) hit = true;
            for (String a : anns) for (String pfx : ep.annotationPrefixes) if (a.startsWith(pfx)) hit = true;
            if (!hit && !ep.supertypePrefixes.isEmpty() && !m.isStatic() && !m.getName().startsWith("<")) {
                boolean superHit = false;
                for (String s : supers) for (String pfx : ep.supertypePrefixes) if (s.startsWith(pfx)) superHit = true;
                if (superHit && (ep.methodNames.isEmpty() || ep.methodNames.contains(m.getName()))) hit = true;
            }
            if (hit) out.add(ep.kind);
        }
        return out;
    }

    public boolean isEntry(SootMethod m) {
        Set<String> k = classify(m);
        k.remove("SHORTLIVED");
        return !k.isEmpty();
    }
}
