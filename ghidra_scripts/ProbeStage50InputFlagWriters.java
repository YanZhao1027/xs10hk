// @category X6
// Stage50: bounded *static* instruction offset scan for Recorder input
// mode flag 0x581 and nearby 0x580/0x583/0x582. Identical offsets on
// different objects DO NOT prove pointer alias. READ ONLY, no edits.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.util.*;
import java.util.regex.*;
public class ProbeStage50InputFlagWriters extends GhidraScript {
  public void run() throws Exception {
    Pattern p=Pattern.compile("\\[(?:r\\d+|sp|lr),#0x(57c|57d|57e|57f|580|581|582|583|584|585|586|587|588|58c|5b0|5b1)\\]");
    Map<String,Integer> totals=new TreeMap<>();
    Map<String,TreeMap<String,ArrayList<String>>> grouped=new TreeMap<>();
    InstructionIterator it=currentProgram.getListing().getInstructions(true);
    while(it.hasNext()&&!monitor.isCancelled()){
      Instruction ins=it.next();
      long site=ins.getAddress().getOffset();
      if(site<0x01021000L||site>0x028a0000L)continue;
      String asm=ins.toString().toLowerCase();
      Matcher ma=p.matcher(asm);
      if(!ma.find())continue;
      String off=ma.group(1);
      String mne=ins.getMnemonicString().toLowerCase();
      String rw=mne.startsWith("str")?"WRITE":mne.startsWith("ldr")?"READ":"OTHER";
      String k=off+"/"+rw;
      totals.put(k,totals.getOrDefault(k,0)+1);
      if(!rw.equals("WRITE")&&!off.matches("58[0-3]"))continue;
      Function owner=getFunctionContaining(ins.getAddress());
      String fn=owner==null?"NO_FUNC":owner.getName()+"@"+owner.getEntryPoint();
      grouped.computeIfAbsent(k,z->new TreeMap<>()).computeIfAbsent(fn,z->new ArrayList<>()).add(String.format("%08x %s",site,asm));
    }
    println("ST50_TOTALS "+totals);
    for(String k:grouped.keySet()){
      println("ST50_GROUP "+k+" fns="+grouped.get(k).size());
      for(Map.Entry<String,ArrayList<String>> e:grouped.get(k).entrySet()){
        println("ST50_OWNER "+k+" "+e.getKey()+" sites="+e.getValue().size());
        for(String line:e.getValue())println("ST50_SITE "+line);
      }
    }
  }
}