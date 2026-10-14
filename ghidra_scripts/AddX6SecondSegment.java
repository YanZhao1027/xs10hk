// Map a private decoded X6 section-2 binary into the same Ghidra program
// as section 1, so that ARM BL xrefs across segments can be recovered.
// @category X6
//
// Args: local_section2.bin 0xBASE 0xENTRY
// This changes ONLY a local Ghidra PROJECT memory map, not the vendor DAT,
// computer USB settings, live RAM, SD card or camera firmware.
import java.io.File;
import java.io.FileInputStream;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class AddX6SecondSegment extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length != 3) {
            throw new Exception("Usage: private_binary base_hex entry_hex");
        }
        File local = new File(a[0]);
        if (!local.isFile()) throw new Exception("Cannot find local file");
        long len = local.length();
        if (len <= 32 || len > 16L * 1024 * 1024) {
            throw new Exception("Unexpected section-2 size: " + len);
        }
        Address base = toAddr(Long.parseUnsignedLong(
                a[1].replace("0x", ""), 16));
        Address entry = toAddr(Long.parseUnsignedLong(
                a[2].replace("0x", ""), 16));
        if (currentProgram.getMemory().getBlock(base) != null) {
            throw new Exception("Section-2 address already mapped");
        }
        if (entry.compareTo(base) < 0 ||
                entry.compareTo(base.add(len - 1)) > 0) {
            throw new Exception("Entry is outside the mapped segment");
        }
        Memory mem = currentProgram.getMemory();
        try (FileInputStream in = new FileInputStream(local)) {
            MemoryBlock block = mem.createInitializedBlock(
                    "X6_SECTION_2", base, in, len, monitor, false);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(true);
        }
        println("X6_MAP added section2 base=" + base + " bytes=" + len);
        println("X6_MAP section2_entry=" + entry +
                " disassemble=" + disassemble(entry));
    }
}
