// Offline-only X6 ARM entrypoint validation for Ghidra analyzeHeadless.
// @category X6
//
// Invoke after importing a decompressed X6 section with the candidate load
// base, e.g. -loader BinaryLoader -loader-baseAddr 0x01021000.
// Post-script args: entry address as unsigned hexadecimal without 0x.
// Disassembles only a small entrypoint window. No camera/USB access.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class InspectX6Entry extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new Exception("Expected one hexadecimal ARM entrypoint address");
        }
        long addressLong = Long.parseUnsignedLong(args[0].replace("0x", ""), 16);
        Address entry = toAddr(addressLong);
        println("X6_SCRIPT language=" + currentProgram.getLanguageID());
        println("X6_SCRIPT entry_candidate=" + entry);
        if (currentProgram.getMemory().getBlock(entry) == null) {
            throw new Exception("Entry not in imported memory; check base address");
        }
        boolean ok = disassemble(entry);
        println("X6_SCRIPT disassembled=" + ok);
        Instruction inst = getInstructionAt(entry);
        for (int i = 0; i < 12 && inst != null; i++) {
            println("X6_ARM " + inst.getAddress() + " " + inst.toString());
            inst = inst.getNext();
        }
    }
}
