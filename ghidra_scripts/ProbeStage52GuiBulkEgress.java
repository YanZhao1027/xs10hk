// @category X6
// Read only GUI base consumers, find potential full-record egress paths.
// This is a bounded function-local search; interprocedural alias and generic
// engine calls may hide paths; missing matches do not prove no data movement.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.*;
public class ProbeStage52GuiBulkEgress extends GhidraScript {
  public void run() throws Exception {
    String[] aa=getScriptArgs();
    if(aa.length!=2)throw new IllegalArgumentException("gui_base copy_helper");
    Address gui=toAddr(Long.parseUnsignedLong(aa[0],16));
    String helper=aa[1].toLowerCase();
    Reference[] rr=getReferencesTo(gui);
    TreeMap<String,Function> funcs=new TreeMap<>();
    for(Reference r:rr){Function f=getFunctionContaining(r.getFromAddress());if(f!=null)funcs.put(f.getEntryPoint().toString(),f);}
    int analysed=0,withCopy=0,withLong=0;
    println("ST52_GUI_REF addr="+gui+" refs="+rr.length+" functions="+funcs.size());
    DecompInterface dc=new DecompInterface();dc.openProgram(currentProgram);
    try{
      for(Function f:funcs.values()){
        if(monitor.isCancelled())break;
        DecompileResults d=dc.decompileFunction(f,15,monitor);
        if(!d.decompileCompleted()||d.getDecompiledFunction()==null)continue;
        analysed++;
        String c=d.getDecompiledFunction().getC();
        String lc=c.toLowerCase();
        boolean cop=lc.contains(helper+"(")||lc.contains("thunk_ext_fun_00059")||lc.contains("memcpy(");
        boolean sized=lc.contains("0x5d8")||lc.contains("0x5dc")||lc.contains("0x600")||lc.contains("0x2000");
        if(cop)withCopy++;
        if(sized)withLong++;
        if(!(cop||sized))continue;
        println("ST52_GUI_CANDIDATE fn="+f.getEntryPoint()+" cop="+cop+" long="+sized);
        String[] lines=c.split("\\n");
        for(int i=0;i<lines.length;i++){
          String low=lines[i].toLowerCase();
          if(low.contains(helper+"(")||low.contains("thunk_ext_fun_00059")||low.contains("memcpy(")||low.contains("0x5dc")||low.contains("0x5d8")||low.contains("0x600")||low.contains("0x2000")||
             (low.contains("0x581")&&low.contains("="))||low.contains("dat_"+gui.toString().toLowerCase())){
            println("ST52_GUI_LINE fn="+f.getEntryPoint()+" ln="+(i+1)+" "+lines[i].trim());
          }
        }
      }
    }finally{dc.dispose();}
    println("ST52_GUI_SUMMARY addr="+gui+" decompiled="+analysed+" with_copy="+withCopy+" with_full_size_literal="+withLong);
  }
}