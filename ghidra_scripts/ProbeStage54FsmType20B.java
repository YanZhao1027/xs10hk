// @category X6
// Private bounded analysis: show only 0x20B-related event classification
// inside a large Recorder state-machine callback, no ROM dump in output.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.util.*;
public class ProbeStage54FsmType20B extends GhidraScript {
 public void run() throws Exception {
  DecompInterface decomp=new DecompInterface();decomp.openProgram(currentProgram);
  try {
   for(String arg:getScriptArgs()){
    Function fn=getFunctionContaining(toAddr(Long.parseUnsignedLong(arg,16)));
    if(fn==null)continue;
    DecompileResults x=decomp.decompileFunction(fn,30,monitor);
    if(!x.decompileCompleted()){println("ST54_NO_C "+arg);continue;}
    String[] lines=x.getDecompiledFunction().getC().split("\\n");
    int refs=0;
    println("ST54_FSM_FUNC="+fn.getEntryPoint()+" lines="+lines.length);
    for(int i=0;i<lines.length;i++){
     if(lines[i].contains("0x20b")||lines[i].contains("0x20B")){
      refs++;
      for(int j=Math.max(0,i-5);j<=Math.min(lines.length-1,i+5);j++)
       println("ST54_FSM_NEAR20B line="+(j+1)+" "+lines[j].trim());
     }
    }
    println("ST54_FSM_20B_COUNT="+refs);
   }
  }finally{decomp.dispose();}
 }
}