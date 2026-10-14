package edu.anon.spotbugs.threadlocal;

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
