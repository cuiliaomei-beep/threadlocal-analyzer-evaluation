package edu.anon.pmd.threadlocal;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.java.ast.ASTAnonymousClassDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTArrayAllocation;
import net.sourceforge.pmd.lang.java.ast.ASTConstructorCall;
import net.sourceforge.pmd.lang.java.ast.ASTExpression;
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTFinallyClause;
import net.sourceforge.pmd.lang.java.ast.ASTFormalParameter;
import net.sourceforge.pmd.lang.java.ast.ASTMethodCall;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTAssignableExpr.ASTNamedReferenceExpr;
import net.sourceforge.pmd.lang.java.ast.JavaNode;
import net.sourceforge.pmd.lang.java.ast.ASTTryStatement;
import net.sourceforge.pmd.lang.java.ast.ASTType;
import net.sourceforge.pmd.lang.java.ast.ASTTypeDeclaration;
import net.sourceforge.pmd.lang.java.ast.ASTVariableId;
import net.sourceforge.pmd.lang.java.ast.JModifier;
import net.sourceforge.pmd.lang.java.ast.TypeNode;
import net.sourceforge.pmd.lang.java.symbols.JVariableSymbol;
import net.sourceforge.pmd.lang.java.types.JArrayType;
import net.sourceforge.pmd.lang.java.types.JClassType;
import net.sourceforge.pmd.lang.java.types.JTypeMirror;
import net.sourceforge.pmd.lang.java.types.TypePrettyPrint;
import net.sourceforge.pmd.lang.java.types.TypeTestUtil;

/**
 * Helper logic of PMD-TL. NOT part of the published document: PMD-TL.md only names these helpers and describes them in
 * prose ("Helper logic", rule table, ruleset properties). This class implements exactly those descriptions; every method
 * quotes the sentence it implements. Written 2026-09-29 for the FSE re-evaluation, looking at the design set only.
 */
final class ThreadLocalAstUtil {

    private ThreadLocalAstUtil() { }

    private static final String[] TL_TYPES = {
        "java.lang.ThreadLocal", "io.netty.util.concurrent.FastThreadLocal", "com.alibaba.ttl.TransmittableThreadLocal",
    };
    /** benign type list of the document */
    private static final Set<String> BENIGN = new HashSet<>(Arrays.asList(
        "java.lang.String", "java.lang.Integer", "java.lang.Long", "java.lang.Boolean", "java.lang.Enum",
        "java.lang.Short", "java.lang.Byte", "java.lang.Character", "java.lang.Float", "java.lang.Double"));
    /** growth-prone initialisers: "arrays, buffers, builders, parsers, serializers, or compression state" */
    private static final String[] GROWTH_HINTS = {
        "StringBuilder", "StringBuffer", "ByteArrayOutputStream", "ByteBuffer", "CharBuffer", "Buffer", "Builder",
        "Parser", "Serializer", "Deflater", "Inflater", "ArrayList", "HashMap", "LinkedList", "HashSet", "ArrayDeque",
    };

    // ------------------------------------------------------------------ types

    static String pretty(JTypeMirror t) {
        try {
            return t == null ? "" : TypePrettyPrint.prettyPrint(t);
        } catch (RuntimeException e) {
            return "";
        }
    }

    static boolean isThreadLocalType(TypeNode node) {
        if (node == null) return false;
        for (String n : TL_TYPES) {
            if (TypeTestUtil.isA(n, node)) return true;
        }
        // unresolved types (dependency not on the auxiliary class path): fall back to the written type name
        String txt = node instanceof JavaNode ? String.valueOf(((JavaNode) node).getText()) : "";
        String p = pretty(node.getTypeMirror());
        return (p.contains("ThreadLocal") && !p.contains("ThreadLocalRandom"))
                || (node instanceof ASTType && txt.contains("ThreadLocal") && !txt.contains("ThreadLocalRandom"));
    }

    /** "known holder": SpotBugs-TL/Infer-TL name ContextHolder-style holders; the receiver is such a type or variable */
    static boolean isHolderReceiver(ASTExpression qualifier) {
        if (qualifier == null) return false;
        String p = pretty(qualifier.getTypeMirror());
        String txt = String.valueOf(qualifier.getText());
        return p.contains("ContextHolder") || txt.contains("ContextHolder");
    }

    /** the value type argument T of ThreadLocal<T>, or null when the type is raw / not resolvable */
    static JTypeMirror valueType(ASTFieldDeclaration field) {
        JTypeMirror t = field.getTypeNode().getTypeMirror();
        return firstThreadLocalArg(t, 0);
    }

    private static JTypeMirror firstThreadLocalArg(JTypeMirror t, int depth) {
        if (!(t instanceof JClassType) || depth > 3) return null;
        JClassType c = (JClassType) t;
        String name = pretty(c.getErasure());
        List<JTypeMirror> args = c.getTypeArgs();
        if (name.contains("ThreadLocal")) return args.isEmpty() ? null : args.get(0);
        for (JTypeMirror a : args) {              // Holder<ThreadLocal<AppObj>>
            JTypeMirror r = firstThreadLocalArg(a, depth + 1);
            if (r != null) return r;
        }
        return null;
    }

    static boolean isJdkOwned(JTypeMirror t) {
        if (t == null) return true;               // unknown: do not claim an application-defined value
        if (t.isPrimitive()) return true;
        if (t instanceof JArrayType) return isJdkOwned(((JArrayType) t).getElementType());
        String n = pretty(t.getErasure());
        return n.startsWith("java.") || n.startsWith("javax.") || n.startsWith("jdk.") || n.startsWith("sun.") || !n.contains(".");
    }

    // ------------------------------------------------------------------ SCO

    private static List<ASTMethodCall> calls(Node scope) {
        return scope.descendants(ASTMethodCall.class).crossFindBoundaries().toList();
    }

    private static boolean isTlCall(ASTMethodCall c, String name, boolean holders) {
        ASTExpression q = c.getQualifier();
        if (q == null) return false;
        if (c.getMethodName().equals(name) && isThreadLocalType(q)) return true;
        if (!holders || !isHolderReceiver(q)) return false;
        String m = c.getMethodName();
        if (name.equals("set")) return m.startsWith("set");
        if (name.equals("remove")) return m.startsWith("remove") || m.startsWith("clear") || m.startsWith("reset") || m.startsWith("unset");
        if (name.equals("get")) return m.startsWith("get");
        return false;
    }

    private static Object symbolOf(ASTExpression q) {
        if (q instanceof ASTNamedReferenceExpr) {
            JVariableSymbol s = ((ASTNamedReferenceExpr) q).getReferencedSym();
            if (s != null) return s;
        }
        return q == null ? "" : String.valueOf(q.getText());
    }

    /** "Find method calls whose name is "set". Check whether the receiver is a ThreadLocal variable or a known holder method." */
    static boolean containsThreadLocalSet(Node method, boolean holders) {
        for (ASTMethodCall c : calls(method)) if (isTlCall(c, "set", holders)) return true;
        return false;
    }

    /** "Find method calls whose name is "remove". Check whether the receiver matches the same ThreadLocal symbol when resolvable." */
    static boolean containsMatchingThreadLocalRemove(Node method, boolean holders) {
        List<Object> set = new ArrayList<>();
        for (ASTMethodCall c : calls(method)) if (isTlCall(c, "set", holders)) set.add(symbolOf(c.getQualifier()));
        for (ASTMethodCall c : calls(method)) {
            if (!isTlCall(c, "remove", holders)) continue;
            Object r = symbolOf(c.getQualifier());
            for (Object s : set) if (s.equals(r) || s instanceof String || r instanceof String) return true;
        }
        return false;
    }

    /** "Inspect try-finally nodes. Check whether remove() appears in the finally block." */
    static boolean containsFinallyRemove(Node method, boolean holders) {
        for (ASTTryStatement t : method.descendants(ASTTryStatement.class).crossFindBoundaries()) {
            ASTFinallyClause f = t.getFinallyClause();
            if (f == null) continue;
            for (ASTMethodCall c : calls(f)) if (isTlCall(c, "remove", holders)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ CLP

    static boolean isStaticField(ASTFieldDeclaration node) {
        return node.hasModifiers(JModifier.STATIC);
    }

    static boolean isThreadLocalField(ASTFieldDeclaration node) {
        return isThreadLocalType(node.getTypeNode());
    }

    /** "static holders": Holder<ThreadLocal<AppObj>> or a ContextHolder-typed static field */
    static boolean isThreadLocalHolderField(ASTFieldDeclaration node) {
        String p = pretty(node.getTypeNode().getTypeMirror());
        String txt = String.valueOf(node.getTypeNode().getText());
        if (isThreadLocalField(node)) return false;
        return p.contains("ThreadLocal<") || txt.contains("ThreadLocal<") || p.contains("ContextHolder") || txt.contains("ContextHolder");
    }

    /** "store application-defined values"; with ignoreJdkTypes, JDK-owned value types are not reported */
    static boolean storesApplicationDefinedValue(ASTFieldDeclaration node, boolean ignoreJdkTypes) {
        JTypeMirror v = valueType(node);
        if (v == null) return false;
        return !ignoreJdkTypes || !isJdkOwned(v);
    }

    /** "anonymous ThreadLocal subclasses whose initialValue() returns application-defined objects" */
    static boolean hasAnonymousInitialValue(ASTFieldDeclaration node) {
        for (ASTVariableId id : node.getVarIds()) {
            ASTExpression init = id.getInitializer();
            if (!(init instanceof ASTConstructorCall) || !((ASTConstructorCall) init).isAnonymousClass()) continue;
            ASTAnonymousClassDeclaration body = ((ASTConstructorCall) init).getAnonymousClassDeclaration();
            if (body == null) continue;
            for (ASTMethodDeclaration m : body.getDeclarations(ASTMethodDeclaration.class)) {
                if (!m.getName().equals("initialValue")) continue;
                ASTType rt = m.getResultTypeNode();
                if (rt != null && !isJdkOwned(rt.getTypeMirror())) return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ CPM

    private static boolean isA(String type, TypeNode n) {
        return n != null && TypeTestUtil.isA(type, n);
    }

    /** "common async-wrapper patterns": Runnable, Callable, Executor and CompletableFuture idioms (one switch per property) */
    static boolean isAsyncBoundaryOrWrapper(ASTMethodDeclaration m, boolean runnable, boolean callable, boolean future, boolean executors) {
        ASTType rt = m.getResultTypeNode();
        List<TypeNode> sig = new ArrayList<>();
        if (rt != null) sig.add(rt);
        for (ASTFormalParameter p : m.getFormalParameters()) sig.add(p.getTypeNode());
        for (TypeNode t : sig) {
            if (runnable && isA("java.lang.Runnable", t)) return true;
            if (callable && (isA("java.util.concurrent.Callable", t) || isA("java.util.function.Supplier", t))) return true;
            if (future && isA("java.util.concurrent.CompletionStage", t)) return true;
            if (executors && isA("java.util.concurrent.Executor", t)) return true;
        }
        ASTTypeDeclaration owner = m.getEnclosingType();
        if (owner != null) {
            if (runnable && m.getName().equals("run") && isA("java.lang.Runnable", owner)) return true;
            if (callable && m.getName().equals("call") && isA("java.util.concurrent.Callable", owner)) return true;
            if (executors && (m.getName().equals("execute") || m.getName().equals("submit")) && isA("java.util.concurrent.Executor", owner)) return true;
        }
        for (ASTMethodCall c : calls(m)) {
            String n = c.getMethodName();
            ASTExpression q = c.getQualifier();
            if (executors && q != null && (n.equals("execute") || n.equals("submit")) && isA("java.util.concurrent.Executor", q)) return true;
            if (future && (n.equals("supplyAsync") || n.equals("runAsync") || n.endsWith("Async"))
                    && q != null && String.valueOf(q.getText()).contains("CompletableFuture")) return true;
        }
        return false;
    }

    static boolean containsThreadLocalGetBeforeSet(ASTMethodDeclaration m) {
        boolean sawGet = false;
        for (ASTMethodCall c : calls(m)) {
            if (isTlCall(c, "get", true)) sawGet = true;
            if (isTlCall(c, "set", true)) return sawGet;
        }
        return false;
    }

    /** "invokes the delegate": run() on a Runnable, call() on a Callable, get() on a Supplier */
    static boolean invokesDelegateRunOrCall(ASTMethodDeclaration m) {
        for (ASTMethodCall c : calls(m)) {
            ASTExpression q = c.getQualifier();
            if (q == null) continue;
            String n = c.getMethodName();
            if (n.equals("run") && isA("java.lang.Runnable", q)) return true;
            if (n.equals("call") && isA("java.util.concurrent.Callable", q)) return true;
            if (n.equals("get") && isA("java.util.function.Supplier", q)) return true;
        }
        return false;
    }

    /** "restored in a finally block": a ThreadLocal set(..) or remove() inside a finally clause */
    static boolean containsRestoreInFinally(ASTMethodDeclaration m) {
        for (ASTTryStatement t : m.descendants(ASTTryStatement.class).crossFindBoundaries()) {
            ASTFinallyClause f = t.getFinallyClause();
            if (f == null) continue;
            for (ASTMethodCall c : calls(f)) if (isTlCall(c, "set", true) || isTlCall(c, "remove", true)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ HVR

    static boolean hasHeavyThreadLocalType(ASTFieldDeclaration node, List<String> heavyTypes) {
        JTypeMirror v = valueType(node);
        if (v == null) return false;
        String p = pretty(v.getErasure());
        for (String h : heavyTypes) {
            String ht = h.trim();
            if (ht.isEmpty()) continue;
            if (p.equals(ht)) return true;
            if (!ht.endsWith("[]") && TypeTestUtil.isA(ht, v)) return true;
        }
        return false;
    }

    /** initialiser (withInitial lambda, anonymous initialValue, constructor argument) allocates an array or a growth-prone object */
    static boolean hasGrowthProneInitializer(ASTFieldDeclaration node) {
        for (ASTVariableId id : node.getVarIds()) {
            ASTExpression init = id.getInitializer();
            if (init == null) continue;
            if (init.descendants(ASTArrayAllocation.class).crossFindBoundaries().nonEmpty()) return true;
            for (ASTConstructorCall c : init.descendants(ASTConstructorCall.class).crossFindBoundaries()) {
                String tn = String.valueOf(c.getTypeNode().getText());
                for (String g : GROWTH_HINTS) if (tn.contains(g)) return true;
            }
        }
        return false;
    }

    /** benign type list of the document; with suppressPrimitiveWrappers the wrappers count as benign */
    static boolean isBenignValueThreadLocal(ASTFieldDeclaration node, boolean suppressPrimitiveWrappers) {
        JTypeMirror v = valueType(node);
        if (v == null) return false;
        String p = pretty(v.getErasure());
        if (p.equals("java.lang.String") || TypeTestUtil.isA("java.lang.Enum", v)) return true;
        return suppressPrimitiveWrappers && BENIGN.contains(p);
    }
}
