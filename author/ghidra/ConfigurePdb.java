import java.io.File;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.program.model.listing.Program;

public class ConfigurePdb extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("PDB path or '-' required");
        boolean enabled = !args[0].equals("-");
        currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("PDB Universal", enabled);
        currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("PDB", false);
        if (enabled) {
            PdbUniversalAnalyzer.setPdbFileOption(currentProgram, new File(args[0]));
            PdbUniversalAnalyzer.setAllowUntrustedOption(currentProgram, false);
        }
    }
}
