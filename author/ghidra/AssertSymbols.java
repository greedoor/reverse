import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class AssertSymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("before/after and report path required");
        boolean after = args[0].equals("after");
        List<String> report = new ArrayList<>();
        for (String name : Arrays.asList("ValidateCandidate", "TransformCandidate", "DeriveTraceKey",
                                        "RestoreDebugBlock", "ExpandTraceBlock", "DecodeTraceOffset")) {
            Function found = null;
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                if (function.getName().contains(name)) found = function;
            }
            if ((found != null) != after) throw new IllegalStateException(args[0] + " symbol mismatch: " + name);
            report.add(name + " : " + (found == null ? "ABSENT" : found.getEntryPoint() + " " + found.getSignature()));
            if (after && name.equals("ValidateCandidate") && !found.getSignature().toString().contains("TRACE_CONTEXT"))
                throw new IllegalStateException("Validator prototype lacks TRACE_CONTEXT");
        }
        String[][] structures = {
            {"TRACE_BLOCK", "flags", "encoded_offset", "decoded_size", "checksum", "encoded_total_size"},
            {"TRACE_CONTEXT", "seed", "key_state", "mode", "permutation", "target"},
            {"TRACE_PROFILE", "mode", "seed_bias", "target_size"},
            {"TRACE_DISPATCH", "mode", "handler", "accepted_status"},
            {"VALIDATION_STATE", "state", "payload_size", "working_key", "transformed"}
        };
        for (String[] expected : structures) {
            Structure found = null;
            Iterator<DataType> types = currentProgram.getDataTypeManager().getAllDataTypes();
            while (types.hasNext()) {
                DataType type = types.next();
                if (type instanceof Structure && type.getName().equals(expected[0])) found = (Structure) type;
            }
            if ((found != null) != after) throw new IllegalStateException(args[0] + " type mismatch: " + expected[0]);
            if (found == null) continue;
            if (expected[0].equals("TRACE_BLOCK") && found.getLength() != 24)
                throw new IllegalStateException("Unexpected TRACE_BLOCK layout");
            for (int i = 1; i < expected.length; ++i) {
                DataTypeComponent component = null;
                for (DataTypeComponent candidate : found.getComponents())
                    if (expected[i].equals(candidate.getFieldName())) component = candidate;
                if (component == null) throw new IllegalStateException("Missing field: " + expected[i]);
                report.add(expected[0] + "." + expected[i] + " : " + component.getOffset());
            }
        }
        report.add("GHIDRA_" + args[0].toUpperCase() + "_PASS");
        Files.write(Path.of(args[1]), report);
    }
}
