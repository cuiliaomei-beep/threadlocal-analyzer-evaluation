package edu.anon.spotbugs.threadlocal;

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
