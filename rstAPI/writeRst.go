package utils

import (
	"fmt"
	"io"
	"sort"

	capnprst "github.com/pangine/pangineDSM-import/capnp-rst"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
	capnp "zombiezen.com/go/capnproto2"
)

// WriteRstFromList output AnalysisRst capnp message to writer from an int list
func WriteRstFromList(offsets []int, writer io.Writer) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		panic("out allocation error")
	}
	data, err := capnprst.NewRootAnalysisRst(seg)
	if err != nil {
		panic("out root error")
	}

	instOffsets, err := capnprst.NewInstOffset(seg)
	if err != nil {
		panic("out inst offset error")
	}
	il, err := capnp.NewInt64List(seg, int32(len(offsets)))
	if err != nil {
		panic("inst offset list create error")
	}
	for i, o := range offsets {
		il.Set(i, int64(o))
	}
	instOffsets.SetOffset(il)
	data.SetInstOffsets(instOffsets)
	err = capnp.NewEncoder(writer).Encode(msg)
	if err != nil {
		panic("capnp message encode fail")
	}
}

// WriteRst depend on whether it is an verbose output
func WriteRst(
	verbose bool,
	instList map[int]pstruct.InstFlags,
	funcList []int,
	writer io.Writer,
	lowbound,
	upbound int,
) {
	// Sort InstFlags
	var offsets []int
	for off := range instList {
		offsets = append(offsets, off)
	}
	sort.Ints(offsets)
	if verbose {
		writeRstVerbose(instList, offsets, funcList, writer, lowbound, upbound)
	} else {
		writeRstCapnp(instList, offsets, funcList, writer)
	}
}

func writeRstVerbose(
	instList map[int]pstruct.InstFlags,
	offsets []int,
	funcList []int,
	writer io.Writer,
	lowbound, upbound int,
) {
	fmt.Fprintln(writer, "----------Function Starts----------")
	for _, fs := range funcList {
		fmt.Fprintln(writer, fs)
	}
	fmt.Fprintln(writer, "----------Instruction Offsets----------")
	for _, i := range offsets {
		if i >= upbound {
			break
		}
		inst, ok := instList[i]
		if ok && inst.OriginInst != "" {
			fmt.Fprintf(writer, "%d\t:%s\t<%d>\n", i, inst.OriginInst, inst.InstSize)
		}
	}
}

// write in format of inst_offset.capnp into the writer
func writeRstCapnp(
	instList map[int]pstruct.InstFlags,
	offsets []int,
	funcList []int,
	writer io.Writer,
) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		panic("out allocation error")
	}
	data, err := capnprst.NewRootAnalysisRst(seg)
	if err != nil {
		panic("out root error")
	}

	instOffsets, err := capnprst.NewInstOffset(seg)
	if err != nil {
		panic("out inst offset error")
	}

	outs := make([]int, 0)
	for _, i := range offsets {
		inst, ok := instList[i]
		if ok && inst.OriginInst != "" {
			outs = append(outs, i)
		}
	}

	il, err := capnp.NewInt64List(seg, int32(len(outs)))
	if err != nil {
		panic("inst offset list create error")
	}
	for i, o := range outs {
		il.Set(i, int64(o))
	}
	instOffsets.SetOffset(il)
	data.SetInstOffsets(instOffsets)

	if len(funcList) > 0 {
		funcStarts, err := capnprst.NewFuncStart(seg)
		if err != nil {
			panic("out func start error")
		}

		fl, err := capnp.NewInt64List(seg, int32(len(funcList)))
		if err != nil {
			panic("func start list create error")
		}
		for i, o := range funcList {
			fl.Set(i, int64(o))
		}
		funcStarts.SetFunc(fl)
		data.SetFuncStarts(funcStarts)
	}

	err = capnp.NewEncoder(writer).Encode(msg)
	if err != nil {
		panic("capnp message encode fail")
	}
}
