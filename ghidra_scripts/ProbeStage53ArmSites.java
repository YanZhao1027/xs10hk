// @category X6
// Bounded read-only disassembly for explicitly selected site windows.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
public class ProbeStage53ArmSites extends GhidraScript {
 public void run() throws Exception {
  for(String token:getScriptArgs()){
   long addr=Long.parseUnsignedLong(token,16);
   println("ST53_WINDOW center="+token);
   for(long a=addr-0x34;a<=addr+0x18;a+=4){
    Address p=toAddr(a);Instruction ins=getInstructionAt(p);
    if(ins!=null)println("ST53_SITE "+p+" "+ins.toString());
   }
  }
 }
}