package tld2;

import soot.G;
import soot.Scene;
import soot.options.Options;

import java.io.File;
import java.util.Collections;
import java.util.List;

public final class SootSetup {
    public static void init(String jar, List<String> extraClasspath) {
        G.reset();
        Options o = Options.v();
        o.set_allow_phantom_refs(true);
        o.set_whole_program(false);
        o.set_src_prec(Options.src_prec_only_class);
        o.set_process_dir(Collections.singletonList(jar));
        o.set_prepend_classpath(true);
        o.set_soot_classpath(String.join(File.pathSeparator, extraClasspath));
        o.set_output_format(Options.output_format_none);
        o.set_keep_line_number(true);
        o.set_no_bodies_for_excluded(true);
        o.set_ignore_resolution_errors(true);
        o.set_ignore_resolving_levels(true);
        o.set_verbose(false);
        o.setPhaseOption("jb", "use-original-names:true");
        o.setPhaseOption("jb.tr", "ignore-nullpointer-dereferences:true");
        Scene.v().loadNecessaryClasses();
    }
}
