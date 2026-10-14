// @category Fujifilm
// Seed a few observed ARM32 branches in a local read-only candidate region.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class XS10Seed extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("XS10_SEED language=" + currentProgram.getLanguage().getLanguageID());
        long[] targets = { 0x001fea10L, 0x00200000L };
        for (long target : targets) {
            Address a = toAddr(target);
            if (!currentProgram.getMemory().contains(a)) {
                println("XS10_SEED outside image " + a);
                continue;
            }
            boolean ok = disassemble(a);
            Instruction instruction = getInstructionAt(a);
            Function f = getFunctionAt(a);
            if (instruction != null && f == null) {
                f = createFunction(a, "research_seed_" + Long.toHexString(target));
            }
            println("XS10_SEED " + a + " disasm=" + ok
                + " instruction=" + (instruction == null ? "none" : instruction.toString())
                + " function=" + (f == null ? "none" : f.getName()));
        }
    }
}

[executed on device: zyubuntu-MS-7E51 (3921990e-de77-4a74-b704-a9c1e6b55713)]