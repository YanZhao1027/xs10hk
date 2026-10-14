// Test raw ARM decoding on the host only. No camera connection.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;

public class ARMProbe extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("XS10_PROBE language=" + currentProgram.getLanguage().getLanguageID());
        println("XS10_PROBE bytes=" + currentProgram.getMemory().getSize());
        Address addr = toAddr(0x200000);
        if (!currentProgram.getMemory().contains(addr)) {
            println("XS10_PROBE address not mapped: " + addr);
            return;
        }
        boolean ok = disassemble(addr);
        println("XS10_PROBE disassemble()=" + ok);
        for (int i = 0; i < 20; i++) {
            Instruction inst = getInstructionAt(addr);
            if (inst == null) { println("XS10_PROBE no instruction at "+addr); break; }
            println("XS10_INST " + addr + " " + inst.toString());
            addr = inst.getMaxAddress().add(1);
        }
        Address start = toAddr(0x200000);
        if (getFunctionAt(start) == null) {
            Function f = createFunction(start, "candidate_200000");
            println("XS10_PROBE createFunction=" + f);
        }
        Function func = getFunctionAt(start);
        println("XS10_PROBE function=" + (func == null ? "none" : func.getName()));
    }
}

[executed on device: zyubuntu-MS-7E51 (3921990e-de77-4a74-b704-a9c1e6b55713)]