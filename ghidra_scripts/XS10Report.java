// @category Fujifilm
// Read-only report from a candidate ARM import; a flat map is not validated.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

public class XS10Report extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("XS10_REPORT file=" + currentProgram.getName());
        println("XS10_REPORT processor=" + currentProgram.getLanguage().getLanguageID());
        println("XS10_REPORT memory=" + currentProgram.getMemory().getSize()
                 + " funcs=" + currentProgram.getFunctionManager().getFunctionCount());
        long[] markers = {0x004845aaL, 0x004a1754L, 0x004ec9eaL,
                          0x00a37cc7L, 0x0048872aL, 0x0048efabL};
        for (long n : markers) {
            Address a = toAddr(n);
            if (!currentProgram.getMemory().contains(a)) continue;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(a);
            int count=0; StringBuilder text = new StringBuilder();
            for (Reference ref : refs) {
                if (count < 8) text.append(" ").append(ref.getFromAddress());
                count++;
            }
            println("XS10_XREF address=" + a + " count=" + count + " first=" + text);
        }
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        long[] starts = {0x00200000L, 0x001fea10L};
        for (long n : starts) {
            Function f = getFunctionAt(toAddr(n));
            if (f == null) continue;
            DecompileResults result = decomp.decompileFunction(f, 25, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                String code = result.getDecompiledFunction().getC();
                println("XS10_CBEGIN " + f.getName() + " " + f.getEntryPoint());
                println(code.substring(0, Math.min(code.length(), 5000)));
                println("XS10_CEND");
            } else {
                println("XS10_DECOMP_FAIL " + f.getName() + " status=" + result.getErrorMessage());
            }
        }
        decomp.dispose();
    }
}
