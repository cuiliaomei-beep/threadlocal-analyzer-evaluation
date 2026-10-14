package edu.anon.spotbugs.threadlocal;

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
