// @category X6
// Only read Ghidra function membership for actual original MOVW #0x20B.
// No exhaustive data-flow or proof of runtime queue delivery.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.util.*;
public class ProbeStage53Message20BOwners extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  TreeMap<String,List<String>> owners=new TreeMap<>();
  for(String s:args){
   Address addr=toAddr(Long.parseUnsignedLong(s.replace("0x",""),16));
   Instruction insn=getInstructionAt(addr);
   Function f=getFunctionContaining(addr);
   String owner=f==null?"NONE":f.getEntryPoint().toString();
   String entry=addr+"="+(insn==null?"NONE":insn.toString());
   if(!owners.containsKey(owner))owners.put(owner,new ArrayList<String>());
   owners.get(owner).add(entry);
  }
  for(Map.Entry<String,List<String>> e:owners.entrySet()){
   println("ST53_20B_FUNC="+e.getKey()+" count="+e.getValue().size()+" sites="+e.getValue());
  }
  println("ST53_20B_SUMMARY sites="+args.length+" owners="+owners.size());
 }
}