package edu.anon.pmd.threadlocal;

import java.util.Arrays;
import java.util.List;

import net.sourceforge.pmd.lang.java.rule.AbstractJavaRulechainRule;
import net.sourceforge.pmd.lang.java.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

/**
 * Rule body as published in PMD-TL.md §4.4, plus the three property descriptors set by the published ruleset.
 * requireLongLivedEvidence is read as "the field is static" (the only long-lived evidence visible on a field declaration).
 */
public class TL_HVR_HeavyValueRetentionRule extends AbstractJavaRulechainRule {

    private static final PropertyDescriptor<List<String>> HEAVY = PropertyFactory.stringListProperty("heavyTypes")
            .desc("Value types considered heavyweight or growth-prone")
            .defaultValue(Arrays.asList("byte[]", "char[]", "java.nio.ByteBuffer", "java.lang.StringBuilder", "java.lang.StringBuffer",
                    "java.io.ByteArrayOutputStream", "java.text.DateFormat", "java.text.SimpleDateFormat",
                    "javax.xml.parsers.DocumentBuilder", "com.fasterxml.jackson.databind.ObjectMapper")).build();
    private static final PropertyDescriptor<Boolean> LONG_LIVED = PropertyFactory.booleanProperty("requireLongLivedEvidence")
            .desc("Report only ThreadLocals with evidence of a long lifetime").defaultValue(true).build();
    private static final PropertyDescriptor<Boolean> SUPPRESS_WRAPPERS = PropertyFactory.booleanProperty("suppressPrimitiveWrappers")
            .desc("Primitive wrappers are benign").defaultValue(true).build();

    public TL_HVR_HeavyValueRetentionRule() {
        super(ASTFieldDeclaration.class);
        definePropertyDescriptor(HEAVY);
        definePropertyDescriptor(LONG_LIVED);
        definePropertyDescriptor(SUPPRESS_WRAPPERS);
    }

    @Override
    public Object visit(ASTFieldDeclaration node, Object data) {
        if (!ThreadLocalAstUtil.isThreadLocalField(node)) {
            return data;
        }
        if (getProperty(LONG_LIVED) && !ThreadLocalAstUtil.isStaticField(node)) {
            return data;
        }

        boolean heavyType = ThreadLocalAstUtil.hasHeavyThreadLocalType(node, getProperty(HEAVY));
        boolean hasGrowthInitializer = ThreadLocalAstUtil.hasGrowthProneInitializer(node);
        boolean benign = ThreadLocalAstUtil.isBenignValueThreadLocal(node, getProperty(SUPPRESS_WRAPPERS));

        if ((heavyType || hasGrowthInitializer) && !benign) {
            asCtx(data).addViolation(node);
        }

        return data;
    }
}
