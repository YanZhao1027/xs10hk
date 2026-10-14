// Trace ARM instructions and decompile the function at a supplied address.
// @category X6
// Args: one or more hexadecimal virtual addresses in an offline X6 Ghidra
// database. All output stays in local logs; no USB or firmware modification.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class TraceX6Function extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try {
            for (String arg : getScriptArgs()) {
                Address address = toAddr(Long.parseUnsignedLong(
                        arg.replace("0x", ""), 16));
                Function func = getFunctionContaining(address);
                println("TRACE_ADDR=" + address + " FUNC=" + (func == null ?
                        "NOT_FOUND" : func.getName() + "@" +
                        func.getEntryPoint() + " SIZE=" +
                        func.getBody().getNumAddresses()));
                Instruction insn = getInstructionContaining(address);
                if (insn != null) {
                    Instruction first = insn;
                    for (int i = 0; i < 18; i++) {
                        Instruction prev = first.getPrevious();
                        if (prev == null) break;
                        first = prev;
                    }
                    for (int i = 0; i < 52 && first != null; i++) {
                        println("TRACE_INSN " + first.getAddress() + " " +
                                first.toString());
                        first = first.getNext();
                    }
                }
                if (func != null) {
                    DecompileResults result =
                        decomp.decompileFunction(func, 32, monitor);
                    println("TRACE_DECOMP_COMPLETED=" +
                            result.decompileCompleted());
                    if (result.decompileCompleted() &&
                            result.getDecompiledFunction() != null) {
                        String c = result.getDecompiledFunction().getC();
                        println("TRACE_DECOMP_BEGIN");
                        println(c.length() <= 18000 ? c :
                                c.substring(0, 18000) + "\n...[truncated]");
                        println("TRACE_DECOMP_END");
                    }
                }
            }
        } finally {
            decomp.dispose();
        }
    }
}
