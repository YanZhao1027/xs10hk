// @category X6
// Read-only inventory of A32 static offsets of driver command context.
// A matching offset on an unrelated base is NOT a proven alias/read of the
// actual 0xFFF7B000 driver command context. No vendor binary changes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.util.*;
import java.util.regex.*;
public class ProbeStage74ContextFieldReaders extends GhidraScript {
  public void run() throws Exception {
    Pattern p=Pattern.compile("\\[(?:r(?:1[0-5]|[0-9])|sp|lr|pc),#0x(600|604|608|60c|610|614|618|61c|620|624|628|62c|630|634|638|63c|820|824|828|82c|830|834|838)\\]");
    TreeMap<String,TreeMap<String,ArrayList<String>>> map=new TreeMap<>();
    TreeMap<String,Integer> totals=new TreeMap<>();
    InstructionIterator it=currentProgram.getListing().getInstructions(true);
    while(it.hasNext() && !monitor.isCancelled()) {
      Instruction ins=it.next();
      long a=ins.getAddress().getOffset();
      if(a<0x01021000L||a>0x028a0000L) continue;
      Matcher m=p.matcher(ins.toString().toLowerCase());
      if(!m.find())continue;
      String off=m.group(1), mn=ins.getMnemonicString().toLowerCase();
      String rw=mn.startsWith("str")?"WRITE":mn.startsWith("ldr")?"READ":"OTHER";
      String key=off+"/"+rw;
      totals.put(key,totals.getOrDefault(key,0)+1);
      Function f=getFunctionContaining(ins.getAddress());
      String owner=f==null?"NO_FUNC":f.getEntryPoint().toString();
      map.computeIfAbsent(key,k->new TreeMap<>()).computeIfAbsent(owner,k->new ArrayList<>())
         .add(ins.getAddress()+" "+ins.toString());
    }
    println("ST74_TOTALS "+totals);
    for(String key:map.keySet()){
      if(!key.startsWith("624/")&&!key.startsWith("828/")&&!key.startsWith("620/")&&!key.startsWith("614/"))continue;
      println("ST74_GROUP "+key+" owners="+map.get(key).size());
      for(Map.Entry<String,ArrayList<String>> f:map.get(key).entrySet()){
        println("ST74_OWNER "+key+" func="+f.getKey()+" sites="+f.getValue().size());
        int count=0;
        for(String line:f.getValue())if(count++<18)println("ST74_SITE "+key+" "+line);
      }
    }
  }
}
