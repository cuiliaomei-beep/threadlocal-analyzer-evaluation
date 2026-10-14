package tld2;

import soot.*;
import soot.jimple.*;
import soot.tagkit.AnnotationTag;
import soot.tagkit.Host;
import soot.tagkit.Tag;
import soot.tagkit.VisibilityAnnotationTag;

import java.util.*;

/** Loaded program: application classes, bodies, hierarchy queries, call resolution (CHA, bounded) and reverse edges. */
public final class Program {
    public final Model model;
    public final List<SootClass> appClasses = new ArrayList<>();
    public final Map<SootMethod, Body> bodies = new LinkedHashMap<>();
    public final FastHierarchy fh;
    /** app-method callers of an app method (reverse CHA edges) */
    public final Map<SootMethod, Set<SootMethod>> callers = new HashMap<>();
    /** per invoke unit: resolved targets (all, including library) */
    public final Map<Unit, Set<SootMethod>> targets = new HashMap<>();
    /** per invoke unit: true when dispatch was too wide to resolve */
    public final Set<Unit> unresolved = new HashSet<>();
    /** `new C` sites outside <clinit>, per class */
    public final Map<SootClass, List<SootMethod>> newSites = new HashMap<>();
    public int bodyErrors = 0, invokeCount = 0;
    public boolean createsPoolsOrThreads = false;
    public final List<SootMethod> delegationSites = new ArrayList<>();

    public Program(Model model) {
        this.model = model;
        // load bodies; LambdaMetaFactory may add synthetic classes while bodies are retrieved, so loop until stable
        Set<SootClass> seen = new HashSet<>();
        boolean changed = true;
        while (changed) {
            changed = false;
            for (SootClass c : new ArrayList<>(Scene.v().getApplicationClasses())) {
                if (!seen.add(c)) continue;
                changed = true;
                appClasses.add(c);
                for (SootMethod m : new ArrayList<>(c.getMethods())) {
                    if (!m.isConcrete()) continue;
                    try {
                        bodies.put(m, m.retrieveActiveBody());
                    } catch (Throwable t) {
                        bodyErrors++;
                    }
                }
            }
        }
        fh = Scene.v().getOrMakeFastHierarchy();
        for (Map.Entry<SootMethod, Body> e : bodies.entrySet()) {
            SootMethod m = e.getKey();
            for (Unit u : e.getValue().getUnits()) {
                Stmt s = (Stmt) u;
                if (s instanceof AssignStmt && ((AssignStmt) s).getRightOp() instanceof NewExpr) {
                    RefType t = ((NewExpr) ((AssignStmt) s).getRightOp()).getBaseType();
                    if (!m.getName().equals("<clinit>"))
                        newSites.computeIfAbsent(t.getSootClass(), k -> new ArrayList<>()).add(m);
                    if (model.poolCreationClasses.contains(t.getClassName())) createsPoolsOrThreads = true;
                }
                if (!s.containsInvokeExpr()) continue;
                invokeCount++;
                InvokeExpr ie = s.getInvokeExpr();
                String key = ie.getMethodRef().getDeclaringClass().getName() + "." + ie.getMethodRef().getName();
                if (model.poolCreationClasses.contains(ie.getMethodRef().getDeclaringClass().getName()) && ie instanceof StaticInvokeExpr)
                    createsPoolsOrThreads = true;
                if (model.delegationMethods.contains(key)) delegationSites.add(m);
                Set<SootMethod> ts = resolve(u, ie);
                targets.put(u, ts);
                for (SootMethod t : ts) if (bodies.containsKey(t)) callers.computeIfAbsent(t, k -> new HashSet<>()).add(m);
            }
        }
    }

    private Set<SootMethod> resolve(Unit u, InvokeExpr ie) {
        try {
            SootMethodRef ref = ie.getMethodRef();
            if (ie instanceof DynamicInvokeExpr) return Collections.emptySet();
            SootMethod decl = ref.tryResolve();
            if (ie instanceof StaticInvokeExpr || ie instanceof SpecialInvokeExpr) {
                return decl == null ? Collections.emptySet() : Collections.singleton(decl);
            }
            InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
            if (decl == null) return Collections.emptySet();
            SootClass base = ref.getDeclaringClass();
            if (iie.getBase().getType() instanceof RefType) base = ((RefType) iie.getBase().getType()).getSootClass();
            Set<SootMethod> ts;
            try {
                ts = fh.resolveAbstractDispatch(base, decl);
            } catch (Throwable t) {
                ts = Collections.singleton(decl);
            }
            if (ts.isEmpty()) ts = Collections.singleton(decl);
            if (ts.size() > model.maxDispatchTargets) {
                unresolved.add(u);
                return Collections.emptySet();
            }
            return ts;
        } catch (Throwable t) {
            return Collections.emptySet();
        }
    }

    public Set<SootMethod> appTargets(Unit u) {
        Set<SootMethod> ts = targets.get(u);
        if (ts == null || ts.isEmpty()) return Collections.emptySet();
        Set<SootMethod> out = new HashSet<>();
        for (SootMethod t : ts) if (bodies.containsKey(t)) out.add(t);
        return out;
    }

    public Set<SootMethod> callersOf(SootMethod m) {
        return callers.getOrDefault(m, Collections.emptySet());
    }

    /** all supertypes (classes + interfaces, transitively) by name; phantom classes contribute their name only */
    public Set<String> supertypeNames(SootClass c) {
        Set<String> out = new LinkedHashSet<>();
        Deque<SootClass> work = new ArrayDeque<>();
        work.add(c);
        while (!work.isEmpty()) {
            SootClass x = work.poll();
            if (!out.add(x.getName())) continue;
            try {
                if (x.hasSuperclass()) work.add(x.getSuperclass());
                for (SootClass i : x.getInterfaces()) work.add(i);
            } catch (Throwable ignored) {
            }
        }
        return out;
    }

    public boolean isSubtypeByName(SootClass c, Set<String> names) {
        for (String n : supertypeNames(c)) if (names.contains(n)) return true;
        return false;
    }

    public static List<String> annotationTypes(Host h) {
        List<String> out = new ArrayList<>();
        for (Tag t : h.getTags()) {
            if (t instanceof VisibilityAnnotationTag) {
                VisibilityAnnotationTag v = (VisibilityAnnotationTag) t;
                if (v.getAnnotations() == null) continue;
                for (AnnotationTag a : v.getAnnotations()) {
                    String ty = a.getType();
                    if (ty.startsWith("L") && ty.endsWith(";")) ty = ty.substring(1, ty.length() - 1).replace('/', '.');
                    out.add(ty);
                }
            }
        }
        return out;
    }

    public static int line(Unit u) {
        int l = u.getJavaSourceStartLineNumber();
        return l < 0 ? 0 : l;
    }
}
