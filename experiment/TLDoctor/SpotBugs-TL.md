# SpotBugs-TL: Customized SpotBugs Detectors for ThreadLocal Misuse Detection

SpotBugs-TL is a bytecode-level adapted baseline for detecting ThreadLocal misuse patterns.
It extends SpotBugs with custom detectors for the four misuse patterns identified in our study: SCO, CLP, CPM, and HVR.
Compared with PMD-TL, SpotBugs-TL works on compiled bytecode and can inspect method calls, field signatures, access flags, and selected control-flow structures.
However, it is still a lightweight adapted baseline rather than a full semantic detector like TLDoctor.

## 1. Detector Design

SpotBugs-TL implements four custom detectors.

| Detector ID                    | Target Pattern | Approximate Detection Logic                                                                                                                                                                               | Limitation                                                                             |
| ------------------------------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `TL_SCO_MISSING_REMOVE`        | SCO            | Detects methods that call `ThreadLocal.set(...)` but do not call `ThreadLocal.remove()` or an equivalent cleanup operation before method exit.                                                            | Mainly intra-procedural; limited wrapper and lifecycle modeling.                       |
| `TL_CLP_STATIC_THREADLOCAL`    | CLP            | Detects `static ThreadLocal` fields, static holders, or anonymous ThreadLocal subclasses that store application-defined objects.                                                                          | Detects class-loader pinning risk but cannot prove an actual class-loader leak.        |
| `TL_CPM_UNBALANCED_CONTEXT`    | CPM            | Detects async wrapper methods that install ThreadLocal context before delegated execution but do not restore the previous context in a `finally`-like cleanup path.                                       | Covers common `Runnable`, `Callable`, `Executor`, and `CompletableFuture` idioms only. |
| `TL_HVR_HEAVY_VALUE_RETENTION` | HVR            | Detects ThreadLocal fields whose generic type, initializer, or bytecode usage suggests heavyweight or growth-prone values, such as arrays, buffers, builders, parsers, serializers, or compression state. | Type- and usage-based heuristic; cannot precisely model workload-dependent growth.     |

It should not be interpreted as equivalent to TLDoctor, because it does not perform full ThreadLocal summary extraction, inter-procedural wrapper resolution, deployment-lifetime reasoning, or balanced async restoration analysis.

## 2. SpotBugs Plugin Configuration

A SpotBugs custom plugin typically contains descriptor files such as:

```text
spotbugs-threadlocal-plugin/
  src/main/resources/findbugs.xml
  src/main/resources/messages.xml
  src/main/resources/bugrank.txt
  src/main/java/edu/example/spotbugs/threadlocal/
      TL_SCO_MissingRemoveDetector.java
      TL_CLP_StaticThreadLocalDetector.java
      TL_CPM_UnbalancedContextDetector.java
      TL_HVR_HeavyValueRetentionDetector.java
      ThreadLocalBytecodeUtil.java
```

### `findbugs.xml`

The `findbugs.xml` file registers detectors and bug patterns.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<FindbugsPlugin
    pluginid="edu.****.spotbugs.threadlocal"
    provider="ThreadLocal Misuse Study"
    website="https://example.org/threadlocal">

    <Detector
        class="edu.****.spotbugs.threadlocal.TL_SCO_MissingRemoveDetector"
        reports="TL_SCO_MISSING_REMOVE"
        speed="fast" />

    <Detector
        class="edu.****.spotbugs.threadlocal.TL_CLP_StaticThreadLocalDetector"
        reports="TL_CLP_STATIC_THREADLOCAL"
        speed="fast" />

    <Detector
        class="edu.****.spotbugs.threadlocal.TL_CPM_UnbalancedContextDetector"
        reports="TL_CPM_UNBALANCED_CONTEXT"
        speed="moderate" />

    <Detector
        class="edu.****.spotbugs.threadlocal.TL_HVR_HeavyValueRetentionDetector"
        reports="TL_HVR_HEAVY_VALUE_RETENTION"
        speed="fast" />

    <BugPattern type="TL_SCO_MISSING_REMOVE"
                abbrev="TL"
                category="CORRECTNESS" />

    <BugPattern type="TL_CLP_STATIC_THREADLOCAL"
                abbrev="TL"
                category="PERFORMANCE" />

    <BugPattern type="TL_CPM_UNBALANCED_CONTEXT"
                abbrev="TL"
                category="CORRECTNESS" />

    <BugPattern type="TL_HVR_HEAVY_VALUE_RETENTION"
                abbrev="TL"
                category="PERFORMANCE" />

</FindbugsPlugin>
```

### `messages.xml`

The `messages.xml` file provides user-facing messages.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<MessageCollection>

    <Detector class="edu.****.spotbugs.threadlocal.TL_SCO_MissingRemoveDetector">
        <Details>
            Detects ThreadLocal values that are installed but not removed before
            the logical method scope exits.
        </Details>
    </Detector>

    <BugPattern type="TL_SCO_MISSING_REMOVE">
        <ShortDescription>ThreadLocal value may not be removed</ShortDescription>
        <LongDescription>
            ThreadLocal value is installed but no matching cleanup operation is found.
        </LongDescription>
        <Details>
            This warning approximates Scope-Cleanup Omission. A ThreadLocal value
            written in a request, task, or callback context may survive on a reused
            worker thread if remove() or an equivalent cleanup operation is missing.
        </Details>
    </BugPattern>

    <BugPattern type="TL_CLP_STATIC_THREADLOCAL">
        <ShortDescription>Static ThreadLocal may pin application-defined values</ShortDescription>
        <LongDescription>
            Static ThreadLocal may retain application-defined values across deployment lifetime.
        </LongDescription>
        <Details>
            This warning approximates Class-Loader Pinning. Static ThreadLocal fields
            or static holders can keep application-defined objects reachable through
            container-managed threads and may prevent class unloading.
        </Details>
    </BugPattern>

    <BugPattern type="TL_CPM_UNBALANCED_CONTEXT">
        <ShortDescription>ThreadLocal context propagation may be unbalanced</ShortDescription>
        <LongDescription>
            ThreadLocal context is installed across an async boundary without guaranteed restoration.
        </LongDescription>
        <Details>
            This warning approximates Context-Propagation Mismatch. A wrapper installs
            ThreadLocal context before delegated execution but does not restore the
            previous value on all paths.
        </Details>
    </BugPattern>

    <BugPattern type="TL_HVR_HEAVY_VALUE_RETENTION">
        <ShortDescription>ThreadLocal may retain heavyweight values</ShortDescription>
        <LongDescription>
            ThreadLocal stores heavyweight or growth-prone values without clear bounding or cleanup.
        </LongDescription>
        <Details>
            This warning approximates Heavyweight-Value Retention. ThreadLocal values
            such as arrays, buffers, builders, parsers, serializers, or compression
            state may retain peak-size memory on long-lived workers.
        </Details>
    </BugPattern>

</MessageCollection>
```

### `bugrank.txt`

A simple `bugrank.txt` can be used to assign priorities.

```text
10 TL_SCO_MISSING_REMOVE
10 TL_CPM_UNBALANCED_CONTEXT
12 TL_CLP_STATIC_THREADLOCAL
14 TL_HVR_HEAVY_VALUE_RETENTION
```

## 3. Enabling SpotBugs-TL

### Maven Configuration

If the project uses the SpotBugs Maven Plugin, SpotBugs-TL can be loaded as an additional plugin dependency.

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.github.spotbugs</groupId>
      <artifactId>spotbugs-maven-plugin</artifactId>
      <version>4.9.8.0</version>
      <configuration>
        <effort>Max</effort>
        <threshold>Low</threshold>
        <plugins>
          <plugin>
            <groupId>edu.****</groupId>
            <artifactId>spotbugs-threadlocal-plugin</artifactId>
            <version>1.0-SNAPSHOT</version>
          </plugin>
        </plugins>
      </configuration>
      <dependencies>
        <dependency>
          <groupId>com.github.spotbugs</groupId>
          <artifactId>spotbugs</artifactId>
          <version>4.9.8</version>
        </dependency>
      </dependencies>
    </plugin>
  </plugins>
</build>
```

Run SpotBugs:

```bash
mvn spotbugs:spotbugs
```

### SpotBugs CLI

The plugin can also be loaded with the SpotBugs command-line interface.

```bash
spotbugs \
  -textui \
  -effort:max \
  -low \
  -pluginList target/spotbugs-threadlocal-plugin-1.0-SNAPSHOT.jar \
  -xml:withMessages \
  -output spotbugs-tl.xml \
  target/classes
```

### Optional Include Filter

An include filter can be used to retain only SpotBugs-TL warnings.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<FindBugsFilter>
    <Match>
        <Bug pattern="TL_SCO_MISSING_REMOVE"/>
    </Match>
    <Match>
        <Bug pattern="TL_CLP_STATIC_THREADLOCAL"/>
    </Match>
    <Match>
        <Bug pattern="TL_CPM_UNBALANCED_CONTEXT"/>
    </Match>
    <Match>
        <Bug pattern="TL_HVR_HEAVY_VALUE_RETENTION"/>
    </Match>
</FindBugsFilter>
```

Example CLI usage:

```bash
spotbugs \
  -textui \
  -include spotbugs-tl-include.xml \
  -pluginList target/spotbugs-threadlocal-plugin-1.0-SNAPSHOT.jar \
  -xml:withMessages \
  -output spotbugs-tl.xml \
  target/classes
```

## 4. Java Detector Implementation

The following illustrate the implementation style.
The exact bytecode checks should be refined depending on the SpotBugs version and the amount of type information available during analysis.

### 4.1 SCO: Missing `remove()`

```java
package edu.****.spotbugs.threadlocal;

import edu.umd.cs.findbugs.BytecodeScanningDetector;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import org.apache.bcel.Const;

public class TL_SCO_MissingRemoveDetector extends BytecodeScanningDetector {

    private final BugReporter bugReporter;

    private boolean sawThreadLocalSet;
    private boolean sawThreadLocalRemove;

    public TL_SCO_MissingRemoveDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitCode(org.apache.bcel.classfile.Code obj) {
        sawThreadLocalSet = false;
        sawThreadLocalRemove = false;
        super.visitCode(obj);

        if (sawThreadLocalSet && !sawThreadLocalRemove) {
            bugReporter.reportBug(new BugInstance(
                    this,
                    "TL_SCO_MISSING_REMOVE",
                    NORMAL_PRIORITY)
                    .addClassAndMethod(this)
                    .addSourceLine(this));
        }
    }

    @Override
    public void sawOpcode(int seen) {
        if (seen != Const.INVOKEVIRTUAL && seen != Const.INVOKEINTERFACE) {
            return;
        }

        String cls = getClassConstantOperand();
        String name = getNameConstantOperand();

        if ("java/lang/ThreadLocal".equals(cls) && "set".equals(name)) {
            sawThreadLocalSet = true;
        }

        if ("java/lang/ThreadLocal".equals(cls) && "remove".equals(name)) {
            sawThreadLocalRemove = true;
        }
    }
}
```

A stronger implementation should distinguish different ThreadLocal receivers and should recognize cleanup performed through wrapper methods.

### 4.2 CLP: Static `ThreadLocal` or Static Holder

```java
package edu.****.spotbugs.threadlocal;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.ba.ClassContext;
import org.apache.bcel.classfile.Field;

public class TL_CLP_StaticThreadLocalDetector implements Detector {

    private final BugReporter bugReporter;

    public TL_CLP_StaticThreadLocalDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {
        for (Field field : classContext.getJavaClass().getFields()) {
            if (!field.isStatic()) {
                continue;
            }

            String sig = field.getSignature();
            if (isThreadLocalSignature(sig) || isThreadLocalHolderSignature(sig)) {
                bugReporter.reportBug(new BugInstance(
                        this,
                        "TL_CLP_STATIC_THREADLOCAL",
                        NORMAL_PRIORITY)
                        .addClass(classContext.getJavaClass())
                        .addField(classContext.getJavaClass().getClassName(),
                                  field.getName(),
                                  field.getSignature(),
                                  true));
            }
        }
    }

    @Override
    public void report() {
        // No global post-processing required.
    }

    private boolean isThreadLocalSignature(String sig) {
        return sig.contains("Ljava/lang/ThreadLocal;");
    }

    private boolean isThreadLocalHolderSignature(String sig) {
        return sig.contains("ThreadLocal")
                || sig.contains("ContextHolder")
                || sig.contains("FastThreadLocal");
    }
}
```

This detector flags deployment-lifetime risk.
A stronger implementation should inspect generic signatures, initializer bytecode, anonymous `initialValue()` subclasses, and whether the stored value is application-defined rather than obviously JDK-owned.

### 4.3 CPM: Unbalanced Context Propagation

```java
package edu.****.spotbugs.threadlocal;

import edu.umd.cs.findbugs.BytecodeScanningDetector;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import org.apache.bcel.Const;

public class TL_CPM_UnbalancedContextDetector extends BytecodeScanningDetector {

    private final BugReporter bugReporter;

    private boolean sawAsyncBoundary;
    private boolean sawThreadLocalGet;
    private boolean sawThreadLocalSet;
    private boolean sawDelegateRunOrCall;
    private boolean sawThreadLocalRestoreOrRemove;

    public TL_CPM_UnbalancedContextDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitCode(org.apache.bcel.classfile.Code obj) {
        sawAsyncBoundary = false;
        sawThreadLocalGet = false;
        sawThreadLocalSet = false;
        sawDelegateRunOrCall = false;
        sawThreadLocalRestoreOrRemove = false;

        super.visitCode(obj);

        if (sawAsyncBoundary
                && sawThreadLocalSet
                && sawDelegateRunOrCall
                && !sawThreadLocalRestoreOrRemove) {
            bugReporter.reportBug(new BugInstance(
                    this,
                    "TL_CPM_UNBALANCED_CONTEXT",
                    NORMAL_PRIORITY)
                    .addClassAndMethod(this)
                    .addSourceLine(this));
        }
    }

    @Override
    public void sawOpcode(int seen) {
        if (seen != Const.INVOKEVIRTUAL
                && seen != Const.INVOKEINTERFACE
                && seen != Const.INVOKESTATIC
                && seen != Const.INVOKESPECIAL) {
            return;
        }

        String cls = getClassConstantOperand();
        String name = getNameConstantOperand();

        if (isThreadLocalClass(cls) && "get".equals(name)) {
            sawThreadLocalGet = true;
        }

        if (isThreadLocalClass(cls) && "set".equals(name)) {
            sawThreadLocalSet = true;
        }

        if (isThreadLocalClass(cls) && ("set".equals(name) || "remove".equals(name))
                && sawDelegateRunOrCall) {
            sawThreadLocalRestoreOrRemove = true;
        }

        if (isAsyncBoundaryClass(cls) || isAsyncFactoryMethod(cls, name)) {
            sawAsyncBoundary = true;
        }

        if (("java/lang/Runnable".equals(cls) && "run".equals(name))
                || ("java/util/concurrent/Callable".equals(cls) && "call".equals(name))) {
            sawDelegateRunOrCall = true;
        }
    }

    private boolean isThreadLocalClass(String cls) {
        return "java/lang/ThreadLocal".equals(cls)
                || cls.endsWith("/FastThreadLocal")
                || cls.endsWith("/TransmittableThreadLocal");
    }

    private boolean isAsyncBoundaryClass(String cls) {
        return cls.contains("Executor")
                || cls.contains("CompletableFuture")
                || cls.contains("Runnable")
                || cls.contains("Callable");
    }

    private boolean isAsyncFactoryMethod(String cls, String name) {
        return cls.contains("CompletableFuture")
                || "submit".equals(name)
                || "execute".equals(name)
                || "supplyAsync".equals(name)
                || "runAsync".equals(name);
    }
}
```

Typical unsafe pattern detected by this rule:

```java
Runnable wrap(Runnable r) {
    Context c = CTX.get();
    return () -> {
        CTX.set(c);
        r.run();          // missing finally restore/remove
    };
}
```

Expected safe pattern:

```java
Runnable wrap(Runnable r) {
    Context c = CTX.get();
    return () -> {
        Context old = CTX.get();
        try {
            CTX.set(c);
            r.run();
        } finally {
            CTX.set(old); // or CTX.remove()
        }
    };
}
```

### 4.4 HVR: Heavyweight Value Retention

```java
package edu.****.spotbugs.threadlocal;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.ba.ClassContext;
import org.apache.bcel.classfile.Field;

public class TL_HVR_HeavyValueRetentionDetector implements Detector {

    private final BugReporter bugReporter;

    public TL_HVR_HeavyValueRetentionDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {
        for (Field field : classContext.getJavaClass().getFields()) {
            String sig = field.getSignature();
            String genericSig = field.getGenericSignature();

            if (!isThreadLocalField(sig, genericSig)) {
                continue;
            }

            if (containsHeavyType(sig) || containsHeavyType(genericSig)) {
                bugReporter.reportBug(new BugInstance(
                        this,
                        "TL_HVR_HEAVY_VALUE_RETENTION",
                        NORMAL_PRIORITY)
                        .addClass(classContext.getJavaClass())
                        .addField(classContext.getJavaClass().getClassName(),
                                  field.getName(),
                                  field.getSignature(),
                                  field.isStatic()));
            }
        }
    }

    @Override
    public void report() {
        // No global post-processing required.
    }

    private boolean isThreadLocalField(String sig, String genericSig) {
        return contains(sig, "java/lang/ThreadLocal")
                || contains(genericSig, "java/lang/ThreadLocal")
                || contains(sig, "FastThreadLocal")
                || contains(genericSig, "FastThreadLocal");
    }

    private boolean containsHeavyType(String sig) {
        if (sig == null) {
            return false;
        }

        return sig.contains("[B")  // byte[]
                || sig.contains("[C")  // char[]
                || sig.contains("java/nio/ByteBuffer")
                || sig.contains("java/lang/StringBuilder")
                || sig.contains("java/lang/StringBuffer")
                || sig.contains("java/io/ByteArrayOutputStream")
                || sig.contains("java/text/DateFormat")
                || sig.contains("java/text/SimpleDateFormat")
                || sig.contains("javax/xml/parsers/DocumentBuilder")
                || sig.contains("javax/xml/parsers/SAXParser")
                || sig.contains("com/fasterxml/jackson/databind/ObjectMapper")
                || sig.contains("java/util/zip/Deflater")
                || sig.contains("java/util/zip/Inflater");
    }

    private boolean contains(String s, String needle) {
        return s != null && s.contains(needle);
    }
}
```

Default heavyweight type list:

```text
byte[]
char[]
java.nio.ByteBuffer
java.lang.StringBuilder
java.lang.StringBuffer
java.io.ByteArrayOutputStream
java.text.DateFormat
java.text.SimpleDateFormat
javax.xml.parsers.DocumentBuilder
javax.xml.parsers.SAXParser
com.fasterxml.jackson.databind.ObjectMapper
java.util.regex.Matcher
java.util.zip.Deflater
java.util.zip.Inflater
```

Benign type list:

```text
java.lang.String
java.lang.Integer
java.lang.Long
java.lang.Boolean
java.lang.Enum
primitive wrappers
small immutable value objects
```
