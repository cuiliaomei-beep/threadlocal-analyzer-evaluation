# PMD-TL: Customized PMD Rules for ThreadLocal Misuse Detection

PMD-TL is a lightweight ThreadLocal-specific adaptation of PMD (Version 7.0.0).
It is designed as a rule-based baseline for comparing whether existing source-level analyzers can approximate the four ThreadLocal misuse patterns identified in our study.
Unlike TLDoctor, PMD-TL does not perform bytecode-level summary propagation, inter-procedural wrapper resolution, deployment-lifetime inference, or balanced restoration checking across complex asynchronous boundaries.

## 1. Rule Design

PMD-TL implements four custom rules, each approximating one ThreadLocal misuse pattern.

| Rule ID                      | Target Pattern | Approximate Detection Logic                                                                                                                                     | Limitation                                                                             |
| ---------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `TL_SCO_MissingRemove`       | SCO            | Detects `ThreadLocal.set(...)` in a method without a corresponding `remove()` in the same method or in a `finally` block.                                       | Mainly local or shallowly inter-procedural.                                            |
| `TL_CLP_StaticThreadLocal`   | CLP            | Detects `static ThreadLocal` fields, static holders, or anonymous `ThreadLocal` subclasses whose `initialValue()` returns application-defined objects.          | Cannot prove a real class-loader leak.                                                 |
| `TL_CPM_UnbalancedContext`   | CPM            | Detects common async-wrapper patterns where ThreadLocal context is installed before delegated execution but not restored in a `finally` block.                  | Only covers common `Runnable`, `Callable`, `Executor`, and `CompletableFuture` idioms. |
| `TL_HVR_HeavyValueRetention` | HVR            | Detects `ThreadLocal` values whose types are likely heavyweight or growth-prone, such as arrays, buffers, builders, parsers, serializers, or compression state. | Type-based heuristic; cannot precisely model workload-dependent growth.                |

Overall, PMD-TL should be interpreted as a lightweight source-level adapted baseline rather than a full semantic detector.

## 2. PMD Ruleset Configuration

```text
rulesets/threadlocal-pmd-ruleset.xml
```

Configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ruleset name="ThreadLocal Custom Rules"
         xmlns="http://pmd.sourceforge.net/ruleset/2.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://pmd.sourceforge.net/ruleset/2.0.0
                             https://pmd.sourceforge.io/ruleset_2_0_0.xsd">

    <description>
        PMD-TL: lightweight ThreadLocal-specific rules for detecting common
        ThreadLocal misuse patterns. These rules are intended as a rule-based
        adapted baseline rather than a full semantic detector.
    </description>

    <rule name="TL_SCO_MissingRemove"
          language="java"
          message="ThreadLocal value is set but not removed before the method exits."
          class="edu.****.pmd.threadlocal.TL_SCO_MissingRemoveRule">
        <description>
            Detects ThreadLocal.set(...) operations in request/task-like methods
            without a corresponding ThreadLocal.remove() in the same method or finally block.
        </description>
        <priority>2</priority>
        <properties>
            <property name="checkFinallyOnly" value="false"/>
            <property name="recognizeHolderMethods" value="true"/>
        </properties>
    </rule>

    <rule name="TL_CLP_StaticThreadLocal"
          language="java"
          message="Static ThreadLocal may retain application-defined values across deployment lifetime."
          class="edu.****.pmd.threadlocal.TL_CLP_StaticThreadLocalRule">
        <description>
            Detects static ThreadLocal fields or static holders that store
            application-defined values and may cause class-loader pinning.
        </description>
        <priority>2</priority>
        <properties>
            <property name="ignoreJdkTypes" value="true"/>
            <property name="checkAnonymousInitialValue" value="true"/>
            <property name="checkStaticHolders" value="true"/>
        </properties>
    </rule>

    <rule name="TL_CPM_UnbalancedContext"
          language="java"
          message="ThreadLocal context is propagated across an async boundary without guaranteed restoration."
          class="edu.****.pmd.threadlocal.TL_CPM_UnbalancedContextRule">
        <description>
            Detects common async propagation patterns where ThreadLocal state is installed
            before delegated execution but not restored in a finally block.
        </description>
        <priority>2</priority>
        <properties>
            <property name="checkRunnable" value="true"/>
            <property name="checkCallable" value="true"/>
            <property name="checkCompletableFuture" value="true"/>
            <property name="checkExecutorWrappers" value="true"/>
        </properties>
    </rule>

    <rule name="TL_HVR_HeavyValueRetention"
          language="java"
          message="ThreadLocal stores heavyweight or growth-prone values without clear bounding or cleanup."
          class="edu.****.pmd.threadlocal.TL_HVR_HeavyValueRetentionRule">
        <description>
            Detects ThreadLocal values whose types are likely heavyweight or growth-prone,
            such as arrays, buffers, builders, parsers, serializers, or compression state.
        </description>
        <priority>3</priority>
        <properties>
            <property name="heavyTypes"
                      value="byte[],char[],java.nio.ByteBuffer,java.lang.StringBuilder,java.lang.StringBuffer,java.io.ByteArrayOutputStream,java.text.DateFormat,java.text.SimpleDateFormat,javax.xml.parsers.DocumentBuilder,com.fasterxml.jackson.databind.ObjectMapper"/>
            <property name="requireLongLivedEvidence" value="true"/>
            <property name="suppressPrimitiveWrappers" value="true"/>
        </properties>
    </rule>

</ruleset>
```

## 3. Enabling PMD-TL

### Maven Configuration

If the project uses the Maven PMD Plugin, PMD-TL can be enabled by adding the custom ruleset and the custom rule implementation dependency.

```xml
<build>
  <plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-pmd-plugin</artifactId>
      <configuration>
        <rulesets>
          <ruleset>rulesets/threadlocal-pmd-ruleset.xml</ruleset>
        </rulesets>
        <targetJdk>${java.version}</targetJdk>
      </configuration>
      <dependencies>
        <dependency>
          <groupId>edu.****</groupId>
          <artifactId>pmd-threadlocal-rules</artifactId>
          <version>1.0-SNAPSHOT</version>
        </dependency>
      </dependencies>
    </plugin>
  </plugins>
</build>
```

Run PMD with Maven:

```bash
mvn pmd:pmd
```

### PMD CLI

Alternatively, PMD-TL can be executed with the PMD command-line interface:

```bash
pmd check \
  -d src/main/java \
  -R rulesets/threadlocal-pmd-ruleset.xml \
  -f text \
  -auxclasspath target/classes
```

## 4. Java Rule Implementation Skeletons

The following skeletons illustrate how the four PMD-TL rules can be implemented.
The exact AST API may need minor adjustments depending on the PMD version used in the experiment.

### 4.1 SCO: Missing `remove()`

```java
package edu.****.pmd.threadlocal;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;

public class TL_SCO_MissingRemoveRule extends AbstractJavaRulechainRule {

    public TL_SCO_MissingRemoveRule() {
        super(ASTMethodDeclaration.class);
    }

    @Override
    public Object visit(ASTMethodDeclaration node, Object data) {
        boolean hasThreadLocalSet = ThreadLocalAstUtil.containsThreadLocalSet(node);
        if (!hasThreadLocalSet) {
            return data;
        }

        boolean hasRemove = ThreadLocalAstUtil.containsMatchingThreadLocalRemove(node);
        boolean hasFinallyRemove = ThreadLocalAstUtil.containsFinallyRemove(node);

        if (!hasRemove && !hasFinallyRemove) {
            asCtx(data).addViolation(node);
        }
        return data;
    }
}
```

Helper logic:

```text
containsThreadLocalSet(method):
  - Find method calls whose name is "set".
  - Check whether the receiver is a ThreadLocal variable or a known holder method.

containsMatchingThreadLocalRemove(method):
  - Find method calls whose name is "remove".
  - Check whether the receiver matches the same ThreadLocal symbol when resolvable.

containsFinallyRemove(method):
  - Inspect try-finally nodes.
  - Check whether remove() appears in the finally block.
```

### 4.2 CLP: Static `ThreadLocal` or Static Holder

```java
package edu.****.pmd.threadlocal;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;

public class TL_CLP_StaticThreadLocalRule extends AbstractJavaRulechainRule {

    public TL_CLP_StaticThreadLocalRule() {
        super(ASTFieldDeclaration.class);
    }

    @Override
    public Object visit(ASTFieldDeclaration node, Object data) {
        if (!ThreadLocalAstUtil.isStaticField(node)) {
            return data;
        }

        boolean isThreadLocal = ThreadLocalAstUtil.isThreadLocalField(node);
        boolean isHolder = ThreadLocalAstUtil.isThreadLocalHolderField(node);

        if (!isThreadLocal && !isHolder) {
            return data;
        }

        boolean storesAppType = ThreadLocalAstUtil.storesApplicationDefinedValue(node);
        boolean hasAnonymousInitialValue = ThreadLocalAstUtil.hasAnonymousInitialValue(node);

        if (storesAppType || hasAnonymousInitialValue) {
            asCtx(data).addViolation(node);
        }
        return data;
    }
}
```

Typical matched patterns:

```java
private static final ThreadLocal<MyContext> CTX = new ThreadLocal<>();

private static final ThreadLocal<Parser> PARSER =
    ThreadLocal.withInitial(Parser::new);

private static final Holder<ThreadLocal<AppObj>> HOLDER = ...;

private static final ThreadLocal<AppObj> LOCAL =
    new ThreadLocal<AppObj>() {
        @Override
        protected AppObj initialValue() {
            return new AppObj();
        }
    };
```

### 4.3 CPM: Unbalanced Context Propagation

```java
package edu.****.pmd.threadlocal;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;

public class TL_CPM_UnbalancedContextRule extends AbstractJavaRulechainRule {

    public TL_CPM_UnbalancedContextRule() {
        super(ASTMethodDeclaration.class);
    }

    @Override
    public Object visit(ASTMethodDeclaration node, Object data) {
        if (!ThreadLocalAstUtil.isAsyncBoundaryOrWrapper(node)) {
            return data;
        }

        boolean snapshotsOld = ThreadLocalAstUtil.containsThreadLocalGetBeforeSet(node);
        boolean installsNew = ThreadLocalAstUtil.containsThreadLocalSet(node);
        boolean invokesDelegate = ThreadLocalAstUtil.invokesDelegateRunOrCall(node);
        boolean restoresOld = ThreadLocalAstUtil.containsRestoreInFinally(node);

        if (installsNew && invokesDelegate && !restoresOld) {
            asCtx(data).addViolation(node);
        }

        return data;
    }
}
```

Typical unsafe pattern:

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
package edu.****.pmd.threadlocal;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;

public class TL_HVR_HeavyValueRetentionRule extends AbstractJavaRulechainRule {

    public TL_HVR_HeavyValueRetentionRule() {
        super(ASTFieldDeclaration.class);
    }

    @Override
    public Object visit(ASTFieldDeclaration node, Object data) {
        if (!ThreadLocalAstUtil.isThreadLocalField(node)) {
            return data;
        }

        boolean heavyType = ThreadLocalAstUtil.hasHeavyThreadLocalType(node);
        boolean hasGrowthInitializer = ThreadLocalAstUtil.hasGrowthProneInitializer(node);
        boolean benign = ThreadLocalAstUtil.isBenignValueThreadLocal(node);

        if ((heavyType || hasGrowthInitializer) && !benign) {
            asCtx(data).addViolation(node);
        }

        return data;
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
