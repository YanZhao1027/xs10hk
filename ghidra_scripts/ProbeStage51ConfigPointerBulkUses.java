// @category X6
// Read-only inventory of functions DIRECTLY referencing current config P
// pointer *slot* and calls to copy/zero helper functions. Evidence bound:
// detecting uses of one slot in a function does NOT prove every memcpy in
// that function targets P, nor detect flows through interprocedural arguments.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.*;
import java.util.regex.*;
public class ProbeStage51ConfigPointerBulkUses extends GhidraScript {
 public void run() throws Exception {
   String[] args=getScriptArgs();
   if(args.length!=2)throw new IllegalArgumentException("hex_slot helper_prefix");
   Address slot=toAddr(Long.parseUnsignedLong(args[0],16));
   String helper=args[1].toLowerCase();
   Reference[] refs=getReferencesTo(slot);
   TreeMap<String,Function> fs=new TreeMap<>();
   for(Reference r:refs){Function f=getFunctionContaining(r.getFromAddress());if(f!=null)fs.put(f.getEntryPoint().toString(),f);}
   println("ST51_SLOT="+slot+" xrefs="+refs.length+" functions="+fs.size());
   DecompInterface dc=new DecompInterface();dc.openProgram(currentProgram);
   int done=0, withCopy=0, withCandidate=0;
   try {
     for(Function f:fs.values()){
       if(monitor.isCancelled())break;
       DecompileResults d=dc.decompileFunction(f,20,monitor);
       if(!d.decompileCompleted()||d.getDecompiledFunction()==null)continue;
       done++;
       String c=d.getDecompiledFunction().getC();
       String[] lines=c.split("\\n");
       boolean hasCopy=c.toLowerCase().contains(helper+"(");
       boolean has581=c.toLowerCase().contains("0x581");
       boolean has5dc=c.toLowerCase().contains("0x5dc")||c.toLowerCase().contains("0x5d8");
       boolean hasAc4=c.toLowerCase().contains("0xac4");
       boolean hasSlot=c.toLowerCase().contains("_dat_"+slot.toString().toLowerCase());
       if(hasCopy)withCopy++;
       if(hasCopy||has581||has5dc){
         withCandidate++;
         println("ST51_CANDIDATE func="+f.getEntryPoint()+" copy="+hasCopy+" byte581="+has581+" size5dc5d8="+has5dc+" indirect_ac4="+hasAc4+" slot_global="+hasSlot+" total_lines="+lines.length);
         for(int i=0;i<lines.length;i++){
           String line=lines[i].trim(),lower=line.toLowerCase();
           boolean keep=lower.contains(helper+"(")||lower.contains("0x581")||lower.contains("0x5dc")||lower.contains("0x5d8")||lower.contains("_dat_"+slot.toString().toLowerCase())||
                        (lower.contains("0xac4")&&lower.contains("="));
           if(keep)println("ST51_LINE fn="+f.getEntryPoint()+" ln="+(i+1)+" "+line);
         }
       }
     }
   }finally{dc.dispose();}
   println("ST51_SUMMARY slot="+slot+" decompiled="+done+" with_helper="+withCopy+" possible="+withCandidate);
 }
}