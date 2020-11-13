//Run function start analyzer once one input program and IO using capnp inst_offset struct
//@author Kaiyuan Li
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import java.io.*;
import java.nio.*;
import java.util.*;

import org.capnproto.PrimitiveList;

import capnp.AnalysisRstJava.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.analyzers.FunctionStartAnalyzer;
import ghidra.app.analyzers.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
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

public class FunctionStartSearch extends GhidraScript {

    public void run() throws Exception {
    	String[] args = getScriptArgs();
    	if (args.length != 1) {
    		println("This script must specify a capnp output");
    		return;
    	}
    	long imgBase = currentProgram.getImageBase().getOffset();
    	// 0x100000 (x64) and 0x10000 (i386) are default image bases ghidra given to 0 image base program.
    	// It is an error way to deal with it, but can keep it simple for now.
    	if (imgBase != 0x100000 && imgBase != 0x10000) imgBase = 0;
        Set<Long> outSet = new TreeSet<>();

        org.capnproto.MessageBuilder messageB = new org.capnproto.MessageBuilder();
        AnalysisRst.Builder anarstB = messageB.initRoot(AnalysisRst.factory);
        InstOffset.Builder isoffB = anarstB.initInstOffsets();
        FuncStart.Builder fnSttB = anarstB.initFuncStarts();

        /*Map<String, String> hana = getCurrentAnalysisOptionsAndValues(currentProgram);
        Map<String, String> analyzers = new TreeMap<>();
        for (String analyzer : hana.keySet()) {
        	String analyzerValue = hana.get(analyzer);
        	analyzers.put(analyzer, analyzerValue);
        }
        for (String analyzer : analyzers.keySet()) {
        	String analyzerValue = analyzers.get(analyzer);
        	boolean isDefault = isAnalysisOptionDefaultValue(currentProgram, analyzer, analyzerValue);
        	println(analyzer + " : " + analyzerValue + (isDefault?" (d)":""));
        }*/

        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        /*Map<String, String> optionsToSet = new HashMap<String, String>();
        optionsToSet.put("ASCII Strings", "false");
        optionsToSet.put("Apply Data Archives", "false");
        optionsToSet.put("Call Convention Identification", "false");
        optionsToSet.put("Create Address Tables", "false");
        optionsToSet.put("Call-Fixup Installer", "false");
        optionsToSet.put("DWARF", "false");
        optionsToSet.put("Data Reference", "false");
        optionsToSet.put("Decompiler Switch Analysis", "false");
        optionsToSet.put("Demangler", "false");
        optionsToSet.put("Disassemble Entry Points", "false");
        optionsToSet.put("ELF Scalar Operand References", "false");
        optionsToSet.put("Embedded Media", "false");
        optionsToSet.put("External Entry References", "false");
        optionsToSet.put("Function ID", "false");
        // Function Start Search on
        optionsToSet.put("GCC Exception Handlers", "false");
        optionsToSet.put("Non-Returning Functions - Discovered", "false");
        optionsToSet.put("Reference", "false");
        optionsToSet.put("Shared Return Calls", "false");
        optionsToSet.put("Stack", "false");
        optionsToSet.put("Subroutine References", "false");
        optionsToSet.put("x86 Constant Reference Analyzer", "false");
        setAnalysisOptions(currentProgram, optionsToSet);*/
    	mgr.startAnalysis(monitor);
        FunctionIterator fit = currentProgram.getListing().getFunctions(true);
        int funcCnt = 0;
        while (fit.hasNext()) {
            Function fnc  = fit.next();
            funcCnt++;
            outSet.add(fnc.getEntryPoint().getOffset() - imgBase);
            //println(Long.toString(fnc.getEntryPoint().getOffset() - imgBase));
        }
        PrimitiveList.Long.Builder fnlst = fnSttB.initFunc(funcCnt);
        fit = currentProgram.getListing().getFunctions(true);
        int i = 0;
        while (fit.hasNext()) {
        	Function fnc  = fit.next();
        	fnlst.set(i, fnc.getEntryPoint().getOffset() - imgBase);
            i++;
        }
    	/*InstructionIterator fit = currentProgram.getListing().getInstructions(true);
        while (fit.hasNext()) {
            Instruction fnc  = fit.next();
            outSet.add(fnc.getAddress().getOffset() - imgBase);
            //println(Long.toString(fnc.getAddress().getOffset() - imgBase));
        }*/
        PrimitiveList.Long.Builder inlst = isoffB.initOffset(outSet.size());
        Iterator<Long> lit = outSet.iterator();
        i = 0;
        while (lit.hasNext()) {
        	inlst.set(i, lit.next());
        	i++;
        }
        try {
        	FileOutputStream outfile = new FileOutputStream(args[0]);
	        org.capnproto.Serialize.write(
	        		outfile.getChannel(),
	        		messageB);
	        println("File writing complete!");
	        outfile.close();
        } catch (FileNotFoundException e) {
        	e.printStackTrace();
        } catch (IOException e) {
        	e.printStackTrace();
        }
    }
}
