package edu.anon.pmd.threadlocal;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

/** Rule body as published in PMD-TL.md §4.2, plus the three property descriptors set by the published ruleset. */
public class TL_CLP_StaticThreadLocalRule extends AbstractJavaRulechainRule {

    private static final PropertyDescriptor<Boolean> IGNORE_JDK = PropertyFactory.booleanProperty("ignoreJdkTypes")
            .desc("Do not report ThreadLocals whose value type is owned by the JDK").defaultValue(true).build();
    private static final PropertyDescriptor<Boolean> CHECK_ANON = PropertyFactory.booleanProperty("checkAnonymousInitialValue")
            .desc("Report anonymous ThreadLocal subclasses whose initialValue() returns an application-defined object").defaultValue(true).build();
    private static final PropertyDescriptor<Boolean> CHECK_HOLDERS = PropertyFactory.booleanProperty("checkStaticHolders")
            .desc("Also inspect static holder fields").defaultValue(true).build();

    public TL_CLP_StaticThreadLocalRule() {
        super(ASTFieldDeclaration.class);
        definePropertyDescriptor(IGNORE_JDK);
        definePropertyDescriptor(CHECK_ANON);
        definePropertyDescriptor(CHECK_HOLDERS);
    }

    @Override
    public Object visit(ASTFieldDeclaration node, Object data) {
        if (!ThreadLocalAstUtil.isStaticField(node)) {
            return data;
        }

        boolean isThreadLocal = ThreadLocalAstUtil.isThreadLocalField(node);
        boolean isHolder = getProperty(CHECK_HOLDERS) && ThreadLocalAstUtil.isThreadLocalHolderField(node);

        if (!isThreadLocal && !isHolder) {
            return data;
        }

        boolean storesAppType = ThreadLocalAstUtil.storesApplicationDefinedValue(node, getProperty(IGNORE_JDK));
        boolean hasAnonymousInitialValue = getProperty(CHECK_ANON) && ThreadLocalAstUtil.hasAnonymousInitialValue(node);

        if (storesAppType || hasAnonymousInitialValue) {
            asCtx(data).addViolation(node);
        }
        return data;
    }
}
