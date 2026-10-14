package tld2;

import com.google.gson.GsonBuilder;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * LifeTL: ThreadLocal obligation checker (FSE-PLAN §3 v2).
 * usage: java -jar LifeTL.jar --jar <file.jar> [--cp a.jar:b.jar] [--out report.json] [--model model.json]
 *        [--disable name,name] [--set limit=value,limit=value] [--timeout seconds]
 */
public final class Main {
    public static void main(String[] args) throws Exception {
        String jar = null, out = null, cp = "", modelFile = null, mode = "full";
        Set<String> disabled = new HashSet<>();
        Map<String, Integer> limits = new LinkedHashMap<>();
        int timeout = 1200;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--jar": jar = args[++i]; break;
                case "--out": out = args[++i]; break;
                case "--cp": cp = args[++i]; break;
                case "--model": modelFile = args[++i]; break;
                case "--mode": mode = args[++i]; break;
                case "--disable": disabled.addAll(Arrays.asList(args[++i].split(","))); break;
                case "--set": for (String kv : args[++i].split(",")) limits.put(kv.split("=")[0], Integer.parseInt(kv.split("=")[1])); break;
                case "--timeout": timeout = Integer.parseInt(args[++i]); break;
                default: throw new IllegalArgumentException("unknown arg " + args[i]);
            }
        }
        if (jar == null) throw new IllegalArgumentException("--jar required");
        final String outPath = out;
        final String jarPath = jar;
        final int timeoutS = timeout;
        final long t0 = System.currentTimeMillis();
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("jar", jar);
        report.put("status", "RUNNING");
        Thread watchdog = new Thread(() -> {
            try {
                Thread.sleep(timeoutS * 1000L);
                synchronized (report) {
                    report.put("status", "TIMEOUT");
                    report.put("time_ms", System.currentTimeMillis() - t0);
                    write(outPath, report);
                }
                System.err.println("TIMEOUT after " + timeoutS + "s: " + jarPath);
                Runtime.getRuntime().halt(3);
            } catch (Exception ignored) {
            }
        });
        watchdog.setDaemon(true);
        watchdog.start();

        PrintStream realErr = System.err;
        try {
            Model model = Model.load(modelFile == null ? null : Paths.get(modelFile), disabled, limits);
            if (!mode.equals("full") && !mode.equals("typestate")) throw new IllegalArgumentException("--mode full|typestate");
            model.classicTypestate = mode.equals("typestate");
            report.put("mode", mode);
            List<String> extra = new ArrayList<>();
            for (String s : cp.split("[:;]")) if (!s.isEmpty()) extra.add(s);
            SootSetup.init(jar, extra);
            Program p = new Program(model);
            long t1 = System.currentTimeMillis();
            TLFinder finder = new TLFinder(p);
            finder.run();
            Typestate ts = new Typestate(p, finder);
            ts.run();
            Facts facts = new Facts(p, finder);
            facts.run();
            Obligations ob = new Obligations(p, finder, ts, facts);
            ob.run();
            long t2 = System.currentTimeMillis();

            List<Map<String, Object>> tls = new ArrayList<>();
            for (TL tl : finder.tls) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", tl.id);
                m.put("kind", tl.kind.name());
                List<String> re = new ArrayList<>();
                for (soot.SootMethod rm : tl.reassignedIn) re.add(rm.getSignature());
                m.put("reassignedIn", re);
                m.put("declClass", tl.declClassName());
                m.put("static", tl.isStatic);
                m.put("runtimeClass", tl.runtimeClass == null ? null : tl.runtimeClass.getName());
                m.put("inheritable", tl.inheritable);
                m.put("withInitial", tl.withInitial);
                m.put("lazyInit", tl.lazyInit);
                m.put("lambdaCaptured", tl.lambdaCaptured);
                m.put("outerCapture", tl.outerCapture);
                m.put("keyApp", tl.keyApp);
                m.put("tlLikeHeuristic", tl.tlLikeHeuristic);
                m.put("host", tl.host);
                m.put("hostReason", tl.hostReason);
                m.put("loader", tl.loader);
                m.put("valueTypes", new ArrayList<>(tl.valueTypes));
                m.put("growable", tl.growable);
                m.put("softWrapped", tl.softWrapped);
                m.put("ctx", new ArrayList<>(tl.ctx));
                m.put("entryMethods", new ArrayList<>(tl.entryMethods));
                Map<String, Integer> ac = new TreeMap<>();
                for (TL.Access a : tl.accesses) ac.merge(a.kind.name(), 1, Integer::sum);
                m.put("accesses", ac);
                Set<String> accessClasses = new TreeSet<>();
                for (TL.Access a : tl.accesses) accessClasses.add(a.method.getDeclaringClass().getName());
                m.put("accessClasses", new ArrayList<>(accessClasses));
                tls.add(m);
            }
            int unknownCtx = 0;
            for (TL tl : finder.tls) if (tl.ctx.contains("UNKNOWN")) unknownCtx++;
            synchronized (report) {
                report.put("status", "OK");
                report.put("classes", p.appClasses.size());
                report.put("methodsWithBody", p.bodies.size());
                report.put("bodyErrors", p.bodyErrors);
                report.put("invokes", p.invokeCount);
                report.put("unresolvedInvokes", p.unresolved.size());
                report.put("tlCount", finder.tls.size());
                report.put("tlUnknownCtx", unknownCtx);
                report.put("orphanAccesses", finder.orphanAccesses);
                report.put("orphanSites", finder.orphanSites);
                report.put("relevantMethods", ts.relevant.size());
                report.put("summaryRounds", ts.rounds);
                report.put("graphErrors", ts.graphErrors);
                report.put("createsPoolsOrThreads", p.createsPoolsOrThreads);
                report.put("delegationSites", p.delegationSites.size());
                report.put("disabled", new ArrayList<>(disabled));
                if (!limits.isEmpty()) report.put("limits", new LinkedHashMap<>(limits));
                report.put("time_load_ms", t1 - t0);
                report.put("time_analysis_ms", t2 - t1);
                report.put("time_ms", System.currentTimeMillis() - t0);
                report.put("tls", tls);
                report.put("warnings", ob.warnings);
                write(outPath, report);
            }
            int reports = 0;
            for (Obligations.Warning w : ob.warnings) if (w.tier.equals("REPORT")) reports++;
            realErr.println("OK " + jar + ": classes=" + p.appClasses.size() + " tls=" + finder.tls.size() + " reports=" + reports + " warnings=" + ob.warnings.size() + " time=" + (System.currentTimeMillis() - t0) + "ms");
            Runtime.getRuntime().halt(0);
        } catch (Throwable t) {
            synchronized (report) {
                report.put("status", "ERROR");
                report.put("error", t.toString());
                report.put("time_ms", System.currentTimeMillis() - t0);
                write(outPath, report);
            }
            t.printStackTrace(realErr);
            Runtime.getRuntime().halt(2);
        }
    }

    static void write(String out, Map<String, Object> report) throws Exception {
        String json = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create().toJson(report);
        if (out == null) System.out.println(json);
        else {
            Path path = Paths.get(out);
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            Files.write(path, json.getBytes(StandardCharsets.UTF_8));
        }
    }
}
