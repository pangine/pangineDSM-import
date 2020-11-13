//output instruction offsets as capnp inst_offset struct
//@author Kaiyuan Li
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

import org.capnproto.PrimitiveList;

import capnp.AnalysisRstJava.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class OffsetOutput extends GhidraScript {

    public void run() throws Exception {
    	String[] args = getScriptArgs();
    	if (args.length != 1) {
    		println("This script must specify exactly one output capnp file");
    		return;
    	}
        org.capnproto.MessageBuilder message = new org.capnproto.MessageBuilder();
        AnalysisRst.Builder anarst = message.initRoot(AnalysisRst.factory);
        InstOffset.Builder  isoff = anarst.initInstOffsets();

        long imgBase = currentProgram.getImageBase().getOffset();
        // 0x100000 (x64) and 0x10000 (i386) are default image bases ghidra given to 0 image base program.
    	// It is an error way to deal with it, but can keep it simple for now.
    	if (imgBase != 0x100000 && imgBase != 0x10000) imgBase = 0;
        InstructionIterator iit = currentProgram.getListing().getInstructions(true);
        Vector<Long> v = new Vector<>();
        while (iit.hasNext()) {
            Instruction inst  = iit.next();
            v.add(inst.getAddress().getOffset() - imgBase);
        }

        PrimitiveList.Long.Builder lst = isoff.initOffset(v.size());
        Enumeration<Long> ve = v.elements();
        int i = 0;
        while (ve.hasMoreElements()) {
        	lst.set(i, ve.nextElement());
        	i++;
        }
        try {
        	FileOutputStream fos = new FileOutputStream(args[0]);
	        org.capnproto.Serialize.write(
	        		(fos).getChannel(),
	        		message);
        	fos.close();
	        println("File writing complete!");
        } catch (FileNotFoundException e) {
        	e.printStackTrace();
        } catch (IOException e) {
        	e.printStackTrace();
        }
    }
}
