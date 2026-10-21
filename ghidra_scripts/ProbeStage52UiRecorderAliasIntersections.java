// @category X6
// Stage52 bounded read-only function intersection of GUI config base
// and Recorder current P-slot / descriptor P pointer. Intersecting
// function *presence* is NOT proof of pointer equality or memcpy identity.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.*;
public class ProbeStage52UiRecorderAliasIntersections extends GhidraScript {
  public void run() throws Exception {
    String[] aa=getScriptArgs();
    if(aa.length!=3)throw new IllegalArgumentException("gui_hex current_slot_hex descriptor_ptr_hex");
    TreeMap<String,Function>[] groups=new TreeMap[3];
    for(int i=0;i<3;i++){
      groups[i]=new TreeMap<>();
      Address address=toAddr(Long.parseUnsignedLong(aa[i],16));
      Reference[] refs=getReferencesTo(address);
      for(Reference ref:refs){Function f=getFunctionContaining(ref.getFromAddress());if(f!=null)groups[i].put(f.getEntryPoint().toString(),f);}
      println("ST52_REF i="+i+" addr="+address+" refs="+refs.length+" functions="+groups[i].size());
    }
    for(int j=1;j<=2;j++){
      TreeSet<String> cross=new TreeSet<>(groups[0].keySet());
      cross.retainAll(groups[j].keySet());
      println("ST52_INTERSECTION gui_base_and="+j+" total="+cross.size());
      DecompInterface dc=new DecompInterface();dc.openProgram(currentProgram);
      try{
        for(String faddr:cross){
          Function f=groups[0].get(faddr);
          println("ST52_BOTH owner="+faddr+" name="+f.getName());
          DecompileResults out=dc.decompileFunction(f,25,monitor);
          if(!out.decompileCompleted()||out.getDecompiledFunction()==null)continue;
          String code=out.getDecompiledFunction().getC();
          String[] lines=code.split("\\n");
          for(int k=0;k<lines.length;k++){
            String t=lines[k].toLowerCase();
            if(t.contains("_dat_"+aa[j].toLowerCase()) || t.contains("dat_"+aa[0].toLowerCase()) ||
               t.contains("0xac4") || t.contains("0x581") || t.contains("0x5b0") ||
               t.contains("0x5dc") || t.contains("0x5d8") || t.contains("memcpy")){
              println("ST52_BOTH_LINE owner="+faddr+" ln="+(k+1)+" "+lines[k].trim());
            }
          }
        }
      }finally{dc.dispose();}
    }
  }
}