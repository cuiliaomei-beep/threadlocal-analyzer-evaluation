package tld2;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

/** Framework model (FSE-PLAN §3.5): every list here is a declared, tunable input; nothing else in the analyser is name-based. */
public final class Model {
    public final Set<String> tlLikeClasses = new HashSet<>();
    /** facade class -> (set names, remove names) */
    public final Map<String, String[][]> facades = new HashMap<>();
    public final List<String> jdkPrefixes = new ArrayList<>();
    public final List<String> neverThrowPrefixes = new ArrayList<>();
    public final Set<String> unknownFactoryMethods = new HashSet<>();
    public final List<String> unknownFactoryClasses = new ArrayList<>();
    public final List<EntryPattern> entryPatterns = new ArrayList<>();
    public Pattern installerNames, endNames, lifecycleEndNames, testClassPattern;
    public final Set<String> growableTypes = new HashSet<>();
    public final List<String> growableNameHints = new ArrayList<>();
    public final Set<String> poolCreationClasses = new HashSet<>();
    public final Set<String> delegationMethods = new HashSet<>();
    public final List<String> longLivedHostHints = new ArrayList<>();
    public final List<String> churnHostHints = new ArrayList<>();
    public final List<String> singletonAnnotations = new ArrayList<>();
    public int maxDispatchTargets = 16, ctxMaxDepth = 14, ctxMaxVisited = 20000, summaryRounds = 6, valueChaseDepth = 3, reportDepth = 2, entryReportDepth = 6;
    /** names of list entries disabled for sensitivity analysis (RQ3.2), e.g. "entry:CONTAINER", "facades", "growable" */
    public final Set<String> disabled = new HashSet<>();
    /** L2 baseline: classic open/close typestate only (see Main --mode typestate) */
    public boolean classicTypestate = false;
    /** component ablation (RQ3), selected with --disable value,ctx,host,lazy,restore,summaries,model; all false by default */
    public boolean ablValue, ablCtx, ablHost, ablLazy, ablRestore, ablSummaries, ablModel;
    private static final Pattern NEVER = Pattern.compile("(?!)");

    public static final class EntryPattern {
        public String kind;
        public List<String> supertypePrefixes = new ArrayList<>();
        public List<String> annotationPrefixes = new ArrayList<>();
        public Set<String> methodNames = new HashSet<>();
        public boolean mainMethod;
    }

    public static Model load(Path file, Set<String> disabled) throws Exception {
        return load(file, disabled, Collections.emptyMap());
    }

    /** limits: overrides of the entries of "limits" in the model file (sensitivity analysis), e.g. reportDepth=3 */
    public static Model load(Path file, Set<String> disabled, Map<String, Integer> limits) throws Exception {
        Reader r = file == null
                ? new InputStreamReader(Objects.requireNonNull(Model.class.getResourceAsStream("/framework-model.json")), StandardCharsets.UTF_8)
                : Files.newBufferedReader(file, StandardCharsets.UTF_8);
        JsonObject o = new Gson().fromJson(r, JsonObject.class);
        Model m = new Model();
        m.disabled.addAll(disabled);
        strs(o, "tlLikeClasses").forEach(m.tlLikeClasses::add);
        if (m.disabled.contains("tlLike")) m.tlLikeClasses.retainAll(Arrays.asList("java.lang.ThreadLocal", "java.lang.InheritableThreadLocal"));
        if (!m.disabled.contains("facades"))
            for (Map.Entry<String, JsonElement> e : o.getAsJsonObject("facades").entrySet()) {
                JsonObject fo = e.getValue().getAsJsonObject();
                m.facades.put(e.getKey(), new String[][]{strs(fo, "set").toArray(new String[0]), strs(fo, "remove").toArray(new String[0])});
            }
        m.jdkPrefixes.addAll(strs(o, "jdkPrefixes"));
        m.neverThrowPrefixes.addAll(strs(o, "neverThrowPrefixes"));
        m.unknownFactoryMethods.addAll(strs(o, "unknownFactoryMethods"));
        m.unknownFactoryClasses.addAll(strs(o, "unknownFactoryClasses"));
        for (JsonElement je : o.getAsJsonArray("entryPatterns")) {
            JsonObject po = je.getAsJsonObject();
            EntryPattern p = new EntryPattern();
            p.kind = po.get("kind").getAsString();
            if (m.disabled.contains("entry:" + p.kind)) continue;
            p.supertypePrefixes.addAll(strs(po, "supertypePrefixes"));
            p.annotationPrefixes.addAll(strs(po, "annotationPrefixes"));
            p.methodNames.addAll(strs(po, "methodNames"));
            p.mainMethod = po.has("mainMethod") && po.get("mainMethod").getAsBoolean();
            m.entryPatterns.add(p);
        }
        m.installerNames = Pattern.compile(o.get("installerNames").getAsString());
        m.endNames = Pattern.compile(o.get("endNames").getAsString());
        m.lifecycleEndNames = Pattern.compile(o.get("lifecycleEndNames").getAsString());
        m.testClassPattern = Pattern.compile(o.get("testClassPattern").getAsString());
        if (!m.disabled.contains("growable")) {
            m.growableTypes.addAll(strs(o, "growableTypes"));
            m.growableNameHints.addAll(strs(o, "growableNameHints"));
        }
        m.poolCreationClasses.addAll(strs(o, "poolCreationClasses"));
        m.delegationMethods.addAll(strs(o, "delegationMethods"));
        if (!m.disabled.contains("hostHints")) {
            m.longLivedHostHints.addAll(strs(o, "longLivedHostHints"));
            m.churnHostHints.addAll(strs(o, "churnHostHints"));
        }
        m.singletonAnnotations.addAll(strs(o, "singletonAnnotations"));
        // single lists switched off for the sensitivity analysis
        if (m.disabled.contains("delegation")) { m.delegationMethods.clear(); m.poolCreationClasses.clear(); }
        if (m.disabled.contains("installerNames")) m.installerNames = NEVER;
        if (m.disabled.contains("endNames")) { m.endNames = NEVER; m.lifecycleEndNames = NEVER; }
        if (m.disabled.contains("singletonAnnotations")) m.singletonAnnotations.clear();
        if (m.disabled.contains("unknownFactory")) { m.unknownFactoryMethods.clear(); m.unknownFactoryClasses.clear(); }
        if (m.disabled.contains("neverThrow")) m.neverThrowPrefixes.clear();
        if (m.disabled.contains("testClass")) m.testClassPattern = NEVER;
        // component ablation
        m.ablValue = m.disabled.contains("value");
        m.ablCtx = m.disabled.contains("ctx");
        m.ablHost = m.disabled.contains("host");
        m.ablLazy = m.disabled.contains("lazy");
        m.ablRestore = m.disabled.contains("restore");
        m.ablSummaries = m.disabled.contains("summaries");
        m.ablModel = m.disabled.contains("model");
        if (m.ablModel) {
            // the framework model is reduced to ThreadLocal and InheritableThreadLocal; only the definition of the Java platform stays
            m.tlLikeClasses.retainAll(Arrays.asList("java.lang.ThreadLocal", "java.lang.InheritableThreadLocal"));
            m.facades.clear(); m.neverThrowPrefixes.clear(); m.unknownFactoryMethods.clear(); m.unknownFactoryClasses.clear();
            m.entryPatterns.clear(); m.growableTypes.clear(); m.growableNameHints.clear(); m.poolCreationClasses.clear();
            m.delegationMethods.clear(); m.longLivedHostHints.clear(); m.churnHostHints.clear(); m.singletonAnnotations.clear();
            m.installerNames = NEVER; m.endNames = NEVER; m.lifecycleEndNames = NEVER; m.testClassPattern = NEVER;
        }
        if (o.has("limits")) {
            JsonObject l = o.getAsJsonObject("limits");
            if (l.has("maxDispatchTargets")) m.maxDispatchTargets = l.get("maxDispatchTargets").getAsInt();
            if (l.has("ctxMaxDepth")) m.ctxMaxDepth = l.get("ctxMaxDepth").getAsInt();
            if (l.has("ctxMaxVisited")) m.ctxMaxVisited = l.get("ctxMaxVisited").getAsInt();
            if (l.has("summaryRounds")) m.summaryRounds = l.get("summaryRounds").getAsInt();
            if (l.has("valueChaseDepth")) m.valueChaseDepth = l.get("valueChaseDepth").getAsInt();
            if (l.has("reportDepth")) m.reportDepth = l.get("reportDepth").getAsInt();
            if (l.has("entryReportDepth")) m.entryReportDepth = l.get("entryReportDepth").getAsInt();
        }
        for (Map.Entry<String, Integer> e : limits.entrySet()) {
            switch (e.getKey()) {
                case "maxDispatchTargets": m.maxDispatchTargets = e.getValue(); break;
                case "ctxMaxDepth": m.ctxMaxDepth = e.getValue(); break;
                case "summaryRounds": m.summaryRounds = e.getValue(); break;
                case "valueChaseDepth": m.valueChaseDepth = e.getValue(); break;
                case "reportDepth": m.reportDepth = e.getValue(); break;
                case "entryReportDepth": m.entryReportDepth = e.getValue(); break;
                default: throw new IllegalArgumentException("unknown limit " + e.getKey());
            }
        }
        return m;
    }

    private static List<String> strs(JsonObject o, String key) {
        List<String> out = new ArrayList<>();
        if (o.has(key)) for (JsonElement e : o.getAsJsonArray(key)) out.add(e.getAsString());
        return out;
    }

    public boolean isJdk(String className) {
        for (String p : jdkPrefixes) if (className.startsWith(p)) return true;
        return false;
    }

    public boolean neverThrows(String className) {
        for (String p : neverThrowPrefixes) if (className.startsWith(p)) return true;
        return false;
    }

    public boolean isUnknownFactory(String className, String methodName) {
        if (unknownFactoryMethods.contains(methodName)) {
            for (String p : unknownFactoryClasses) if (className.startsWith(p)) return true;
        }
        return methodName.equals("newInstance") || className.equals("java.util.ServiceLoader");
    }

    public boolean isTestClass(String className) {
        return testClassPattern.matcher(className).find();
    }

    private static final java.util.List<String> BUFFER_HINTS = java.util.Arrays.asList("StringBuilder", "StringBuffer", "ByteArrayOutputStream", "CharArrayWriter", "StringWriter", "ByteBuffer", "CharBuffer", "Buffer", "Builder", "Writer", "OutputStream");

    /** buffer-like values whose clear()/reset()/setLength(0) keeps the grown capacity */
    public boolean isBufferType(String className) {
        if (ablModel) return false;
        String simple = className.substring(className.lastIndexOf('.') + 1);
        for (String h : BUFFER_HINTS) if (simple.endsWith(h)) return true;
        return false;
    }

    public boolean isGrowableType(String className) {
        if (growableTypes.contains(className)) return true;
        String simple = className.substring(className.lastIndexOf('.') + 1);
        for (String h : growableNameHints) if (simple.endsWith(h)) return true;
        return false;
    }
}
