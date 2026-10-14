package edu.anon.pmd.threadlocal;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

/** Rule body as published in PMD-TL.md §4.3, plus the four property descriptors set by the published ruleset. */
public class TL_CPM_UnbalancedContextRule extends AbstractJavaRulechainRule {

    private static final PropertyDescriptor<Boolean> RUNNABLE = PropertyFactory.booleanProperty("checkRunnable")
            .desc("Runnable wrappers").defaultValue(true).build();
    private static final PropertyDescriptor<Boolean> CALLABLE = PropertyFactory.booleanProperty("checkCallable")
            .desc("Callable wrappers").defaultValue(true).build();
    private static final PropertyDescriptor<Boolean> FUTURE = PropertyFactory.booleanProperty("checkCompletableFuture")
            .desc("CompletableFuture idioms").defaultValue(true).build();
    private static final PropertyDescriptor<Boolean> EXECUTORS = PropertyFactory.booleanProperty("checkExecutorWrappers")
            .desc("Executor wrappers").defaultValue(true).build();

    public TL_CPM_UnbalancedContextRule() {
        super(ASTMethodDeclaration.class);
        definePropertyDescriptor(RUNNABLE);
        definePropertyDescriptor(CALLABLE);
        definePropertyDescriptor(FUTURE);
        definePropertyDescriptor(EXECUTORS);
    }

    @Override
    public Object visit(ASTMethodDeclaration node, Object data) {
        if (!ThreadLocalAstUtil.isAsyncBoundaryOrWrapper(node, getProperty(RUNNABLE), getProperty(CALLABLE), getProperty(FUTURE), getProperty(EXECUTORS))) {
            return data;
        }

        boolean snapshotsOld = ThreadLocalAstUtil.containsThreadLocalGetBeforeSet(node);
        boolean installsNew = ThreadLocalAstUtil.containsThreadLocalSet(node, true);
        boolean invokesDelegate = ThreadLocalAstUtil.invokesDelegateRunOrCall(node);
        boolean restoresOld = ThreadLocalAstUtil.containsRestoreInFinally(node);

        if (installsNew && invokesDelegate && !restoresOld) {
            asCtx(data).addViolation(node);
        }

        return data;
    }
}
