// Trace X6 ARM references by absolute virtual address, offline only.
// @category X6
// Args: one or more hex virtual addresses in the imported Ghidra project.
// Imported code must use the probable X6 memory base; no USB access.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class ProbeX6Refs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("PROBE language=" + currentProgram.getLanguageID());
        println("PROBE name=" + currentProgram.getName());
        for (String arg : getScriptArgs()) {
            Address target = toAddr(Long.parseUnsignedLong(
                    arg.replace("0x", ""), 16));
            Reference[] refs = getReferencesTo(target);
            println("PROBE_TARGET addr=" + target + " refs=" + refs.length);
            int max = Math.min(refs.length, 22);
            for (int i = 0; i < max; i++) {
                Reference ref = refs[i];
                Address src = ref.getFromAddress();
                Instruction instruction = getInstructionContaining(src);
                println("PROBE_REF from=" + src + " to=" + target +
                        " type=" + ref.getReferenceType() +
                        " insn=" + (instruction == null ? "NONE" : instruction.toString()));
            }
        }
    }
}
