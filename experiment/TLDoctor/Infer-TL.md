# Infer-TL: Customized Infer Adaptation for ThreadLocal Misuse Detection

Infer-TL is a lightweight ThreadLocal-specific adaptation of Infer.
It is designed to evaluate how far an existing inter-procedural static analyzer can be adapted to detect ThreadLocal misuse patterns.
The adaptation combines three parts:

1. Infer's default Java analysis;
2. ThreadLocal-specific configuration and modeling;
3. a post-processing layer that maps Infer reports and additional ThreadLocal facts to four misuse categories.

This adaptation is intended as an experimental baseline rather than a fully dedicated ThreadLocal analysis.

## 1. Rule Design

Infer-TL approximates the four ThreadLocal misuse patterns using a combination of method-call facts, field properties, type information, and post-processed report matching.

| Rule ID                      | Target Pattern | Approximate Detection Logic                                                                                                                                                  | Limitation                                                                                                          |
| ---------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `TL_SCO_MissingRemove`       | SCO            | Detects methods or reachable call chains where `ThreadLocal.set(...)` occurs without a corresponding `remove()` or equivalent cleanup before the logical method scope exits. | Stronger than purely local rules, but still limited by call-graph precision and missing framework lifecycle models. |
| `TL_CLP_StaticThreadLocal`   | CLP            | Detects static `ThreadLocal` fields or static holder objects whose stored values are application-defined types.                                                              | Identifies deployment-lifetime risk but cannot prove a concrete class-loader leak.                                  |
| `TL_CPM_UnbalancedContext`   | CPM            | Detects async propagation wrappers that read a ThreadLocal value, install it in delegated execution, and fail to restore the previous value on all paths.                    | Covers common executor and future idioms; complex framework callbacks may be missed.                                |
| `TL_HVR_HeavyValueRetention` | HVR            | Detects ThreadLocal values whose declared or inferred types are heavyweight or growth-prone, such as arrays, buffers, builders, serializers, parsers, or compression state.  | Type- and usage-driven heuristic; workload-dependent growth is approximated.                                        |

## 2. Infer Configuration

A practical Infer-TL setup can use an `.inferconfig` file to keep the analysis options reproducible.

Example `.inferconfig`:

```json
{
  "analyzer": ["biabduction", "pulse", "liveness"],
  "issues_tests": [],
  "project_root": ".",
  "continue_analysis": true,
  "keep_going": true,
  "debug": false,
  "pulse": true
}
```

For Java projects, Infer can be run through the project build command.
For Maven projects:

```bash
infer run -- mvn -DskipTests compile
```

For Gradle projects:

```bash
infer run -- ./gradlew compileJava
```

The default Infer output can be exported as JSON for post-processing:

```bash
infer report --json > infer-report.json
```

Infer-TL then applies a ThreadLocal-specific post-processing step:

```bash
python infer_tl_postprocess.py \
  --infer-report infer-report.json \
  --source-root src/main/java \
  --output infer-tl-report.json
```

The post-processing script extracts ThreadLocal-related facts from source files, bytecode metadata when available, and Infer reports.
It then classifies candidate warnings into SCO, CLP, CPM, and HVR.

## 3. ThreadLocal Fact Extraction

Infer-TL maintains a lightweight fact database.

```json
{
  "threadlocals": [
    {
      "id": "com.example.ContextHolder.CTX",
      "field": "CTX",
      "owner": "com.example.ContextHolder",
      "static": true,
      "type": "java.lang.ThreadLocal<com.example.RequestContext>",
      "valueType": "com.example.RequestContext"
    }
  ],
  "effects": [
    {
      "method": "com.example.Filter.doFilter",
      "threadlocal": "com.example.ContextHolder.CTX",
      "effect": "set",
      "line": 42
    },
    {
      "method": "com.example.Filter.doFilter",
      "threadlocal": "com.example.ContextHolder.CTX",
      "effect": "remove",
      "line": 58
    }
  ],
  "asyncBoundaries": [
    {
      "method": "com.example.ContextAwareExecutor.wrap",
      "kind": "Runnable",
      "delegateCall": "run"
    }
  ]
}
```

The following source-level and report-level facts are extracted:

* `ThreadLocal` field declarations;
* `ThreadLocal.withInitial(...)` initializers;
* anonymous `ThreadLocal` subclasses and `initialValue()` methods;
* calls to `get()`, `set(...)`, and `remove()`;
* holder methods such as `ContextHolder.set(...)`, `clear(...)`, and `get(...)`;
* async wrappers involving `Runnable`, `Callable`, `Executor`, `CompletableFuture`, and listener callbacks;
* heavyweight value types, including arrays, buffers, builders, parsers, serializers, and compression objects.

## 4. Rule Implementation Sketch

Infer-TL can be implemented as a post-processing layer over Infer reports and extracted ThreadLocal facts.

### 4.1 SCO: Missing `remove()`

```python
def detect_sco(threadlocals, effects, method_summaries):
    warnings = []

    for tl in threadlocals:
        writes = find_effects(effects, tl["id"], effect="set")

        for write in writes:
            method = write["method"]

            if not is_task_or_request_like(method, method_summaries):
                continue

            if has_matching_cleanup(tl["id"], method, effects, method_summaries):
                continue

            warnings.append({
                "type": "TL_SCO_MissingRemove",
                "threadlocal": tl["id"],
                "method": method,
                "line": write["line"],
                "message": "ThreadLocal value is set without guaranteed cleanup."
            })

    return warnings
```

The helper `has_matching_cleanup(...)` checks whether the same ThreadLocal object is removed in the same method, in a known cleanup wrapper, or in a summarized callee.

### 4.2 CLP: Static `ThreadLocal`

```python
def detect_clp(threadlocals):
    warnings = []

    for tl in threadlocals:
        if not tl.get("static", False):
            continue

        value_type = tl.get("valueType", "")

        if is_jdk_owned_type(value_type):
            continue

        warnings.append({
            "type": "TL_CLP_StaticThreadLocal",
            "threadlocal": tl["id"],
            "field": tl["field"],
            "message": "Static ThreadLocal may retain application-defined values."
        })

    return warnings
```

Typical reported cases include:

```java
private static final ThreadLocal<RequestContext> CTX =
    new ThreadLocal<>();

private static final ThreadLocal<Parser> PARSER =
    ThreadLocal.withInitial(Parser::new);
```

### 4.3 CPM: Unbalanced Context Propagation

```python
def detect_cpm(threadlocals, effects, async_boundaries):
    warnings = []

    for boundary in async_boundaries:
        method = boundary["method"]

        for tl in threadlocals:
            has_snapshot = has_effect_before_delegate(effects, tl["id"], method, "get")
            has_install = has_effect_before_delegate(effects, tl["id"], method, "set")
            has_restore = has_restore_after_delegate(effects, tl["id"], method)

            if has_install and not has_restore:
                warnings.append({
                    "type": "TL_CPM_UnbalancedContext",
                    "threadlocal": tl["id"],
                    "method": method,
                    "message": "ThreadLocal context is installed across an async boundary without guaranteed restoration."
                })

    return warnings
```

Unsafe pattern:

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

```python
HEAVY_TYPES = {
    "byte[]",
    "char[]",
    "java.nio.ByteBuffer",
    "java.lang.StringBuilder",
    "java.lang.StringBuffer",
    "java.io.ByteArrayOutputStream",
    "java.text.DateFormat",
    "java.text.SimpleDateFormat",
    "javax.xml.parsers.DocumentBuilder",
    "javax.xml.parsers.SAXParser",
    "com.fasterxml.jackson.databind.ObjectMapper",
    "java.util.regex.Matcher",
    "java.util.zip.Deflater",
    "java.util.zip.Inflater",
}

BENIGN_TYPES = {
    "java.lang.String",
    "java.lang.Integer",
    "java.lang.Long",
    "java.lang.Boolean",
    "java.lang.Enum",
}

def detect_hvr(threadlocals, effects):
    warnings = []

    for tl in threadlocals:
        value_type = normalize_type(tl.get("valueType", ""))

        if value_type in BENIGN_TYPES:
            continue

        if value_type not in HEAVY_TYPES and not looks_growth_prone(value_type):
            continue

        if has_bounding_or_reset_logic(tl["id"], effects):
            continue

        warnings.append({
            "type": "TL_HVR_HeavyValueRetention",
            "threadlocal": tl["id"],
            "valueType": value_type,
            "message": "ThreadLocal stores heavyweight or growth-prone values without clear bounding or cleanup."
        })

    return warnings
```

Heavyweight type list:

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

## 5. Output Format

Infer-TL can emit a JSON report compatible with the evaluation pipeline.

```json
[
  {
    "tool": "Infer-TL",
    "type": "TL_SCO_MissingRemove",
    "pattern": "SCO",
    "project": "example-project",
    "file": "src/main/java/com/example/Filter.java",
    "method": "com.example.Filter.doFilter",
    "line": 42,
    "threadlocal": "com.example.ContextHolder.CTX",
    "message": "ThreadLocal value is set without guaranteed cleanup."
  },
  {
    "tool": "Infer-TL",
    "type": "TL_HVR_HeavyValueRetention",
    "pattern": "HVR",
    "project": "example-project",
    "file": "src/main/java/com/example/BufferCache.java",
    "line": 17,
    "threadlocal": "com.example.BufferCache.BUF",
    "valueType": "byte[]",
    "message": "ThreadLocal stores heavyweight or growth-prone values without clear bounding or cleanup."
  }
]
```

## 6. Recommended Experimental Usage

Workflow:

```bash
infer run -- mvn -DskipTests compile
infer report --json > infer-report.json

python collect_threadlocal_facts.py \
  --source-root src/main/java \
  --output threadlocal-facts.json

python infer_tl_postprocess.py \
  --infer-report infer-report.json \
  --facts threadlocal-facts.json \
  --output infer-tl-report.json
```

For each project, the evaluation records:

* total number of Infer-TL warnings;
* warning counts by pattern: SCO, CLP, CPM, and HVR;
* matched labeled issues on Dataset A;
* false positives and false negatives under the issue-level matching protocol;
* total runtime and average runtime per project.

## 7. Limitations

Infer-TL is an adapted baseline and has several limitations.

First, it depends on the precision of the extracted ThreadLocal facts and the underlying Infer analysis.
Second, complex framework lifecycle behavior may not be visible to the post-processing layer.
Third, async propagation is approximated through common wrapper idioms, so deeply nested callback protocols may be missed.
Fourth, HVR detection relies on type and usage heuristics, which may confuse intentional caching with harmful long-lived retention.
Finally, CLP detection identifies deployment-lifetime risk but does not prove that a concrete class-loader leak will occur at runtime.
