package edu.anon.spotbugs.threadlocal;

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
