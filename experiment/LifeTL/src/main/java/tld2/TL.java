package tld2;

import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.Value;

import java.util.*;

/** Abstract ThreadLocal object ℓ (FSE-PLAN §3.2) together with its layer-1 facts and its access sites. */
public final class TL {
    /** FIELD: a field of ThreadLocal type; FACADE: MDC-like static facade; ALLOC: `new ThreadLocal` never stored in a field
     *  (kept in a local / collection / returned); SELF: a ThreadLocal subclass whose own methods call this.set/get/remove and
     *  which is not tied to exactly one field. */
    public enum Kind { FIELD, FACADE, ALLOC, SELF }
    public enum AKind { SET, SET_NULL, GET, REMOVE }

    public final String id;
    public final Kind kind;
    public final SootField field;        // null unless FIELD
    public final SootClass declClass;    // declaring class (facade: the facade class itself, may be phantom)
    public final boolean isStatic;
    public String facadeClass;
    public SootMethod allocMethod;       // ALLOC: the allocating method
    public Unit allocUnit;

    // declaration facts (Decl)
    public SootClass runtimeClass;       // R: class of the object stored into the field (may be null)
    public boolean inheritable, withInitial, lazyInit, outerCapture, keyApp, tlLikeHeuristic;
    public int lambdaCaptured;
    public soot.SootMethodRef supplierImpl;  // withInitial(lambda) implementation method (raw invokedynamic case)
    public final List<SootMethod> reassignedIn = new ArrayList<>();   // field re-assigned outside <init>/<clinit> (key churn)
    public String host = "UNKNOWN", hostReason = "";

    // value facts (Val)
    public String loader = "UNKNOWN";      // JDK | APP | UNKNOWN
    public final Set<String> valueTypes = new TreeSet<>();
    public boolean growable, softWrapped, valueUnknownFactory, contentChased, contentCleared, bufferValue;

    // thread-context facts (Ctx)
    public final Set<String> ctx = new TreeSet<>();          // CONTAINER | POOLED | LONGLIVED | SHORTLIVED | UNKNOWN
    public final Set<String> entryMethods = new TreeSet<>(); // sample of classified entry methods

    public final List<Access> accesses = new ArrayList<>();

    public TL(String id, Kind kind, SootField field, SootClass declClass, boolean isStatic) {
        this.id = id; this.kind = kind; this.field = field; this.declClass = declClass; this.isStatic = isStatic;
    }

    public static final class Access {
        public final TL tl;
        public final SootMethod method;
        public final Unit unit;
        public final AKind kind;
        public final Value arg;      // set argument (may be null)
        public final Value result;   // get result local (may be null)

        public Access(TL tl, SootMethod method, Unit unit, AKind kind, Value arg, Value result) {
            this.tl = tl; this.method = method; this.unit = unit; this.kind = kind; this.arg = arg; this.result = result;
        }
    }

    public boolean hasAccess(SootMethod m, AKind k) {
        for (Access a : accesses) if (a.method.equals(m) && a.kind == k) return true;
        return false;
    }

    public boolean hasAnyAccess(AKind k) {
        for (Access a : accesses) if (a.kind == k) return true;
        return false;
    }

    public Set<SootMethod> accessMethods() {
        Set<SootMethod> out = new LinkedHashSet<>();
        for (Access a : accesses) out.add(a.method);
        return out;
    }

    public String declClassName() { return declClass == null ? "?" : declClass.getName(); }

    @Override public String toString() { return id; }
}
