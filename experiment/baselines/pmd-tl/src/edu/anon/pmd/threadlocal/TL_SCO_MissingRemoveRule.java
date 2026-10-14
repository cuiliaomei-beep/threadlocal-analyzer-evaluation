package edu.anon.pmd.threadlocal;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTMethodDeclaration;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

/**
 * Rule body as published in PMD-TL.md §4.1. Added: the two property descriptors that the published ruleset sets
 * (checkFinallyOnly, recognizeHolderMethods); PMD rejects a ruleset that sets a property the rule does not define.
 */
public class TL_SCO_MissingRemoveRule extends AbstractJavaRulechainRule {

    private static final PropertyDescriptor<Boolean> CHECK_FINALLY_ONLY = PropertyFactory.booleanProperty("checkFinallyOnly")
            .desc("Accept a remove() only when it is inside a finally block").defaultValue(false).build();
    private static final PropertyDescriptor<Boolean> RECOGNIZE_HOLDERS = PropertyFactory.booleanProperty("recognizeHolderMethods")
            .desc("Treat ContextHolder-style set/clear methods as ThreadLocal set/remove").defaultValue(true).build();

    public TL_SCO_MissingRemoveRule() {
        super(ASTMethodDeclaration.class);
        definePropertyDescriptor(CHECK_FINALLY_ONLY);
        definePropertyDescriptor(RECOGNIZE_HOLDERS);
    }

    @Override
    public Object visit(ASTMethodDeclaration node, Object data) {
        boolean holders = getProperty(RECOGNIZE_HOLDERS);
        boolean hasThreadLocalSet = ThreadLocalAstUtil.containsThreadLocalSet(node, holders);
        if (!hasThreadLocalSet) {
            return data;
        }

        boolean hasRemove = !getProperty(CHECK_FINALLY_ONLY) && ThreadLocalAstUtil.containsMatchingThreadLocalRemove(node, holders);
        boolean hasFinallyRemove = ThreadLocalAstUtil.containsFinallyRemove(node, holders);

        if (!hasRemove && !hasFinallyRemove) {
            asCtx(data).addViolation(node);
        }
        return data;
    }
}
