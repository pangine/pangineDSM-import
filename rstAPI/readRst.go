package utils

import (
	"os"

	capnprst "github.com/pangine/pangineDSM-import/capnp-rst"
	capnp "zombiezen.com/go/capnproto2"
)

// ReadRst reads the AnalysisRst capnp file into int lists
func ReadRst(f string) (ety []int, fnc []int) {
	b, err := os.Open(f)
	if err != nil {
		//panic(err)
		return
	}
	defer b.Close()

	msg, err := capnp.NewDecoder(b).Decode()
	if err != nil {
		panic("capnp decode error")
	}
	data, err := capnprst.ReadRootAnalysisRst(msg)
	if err != nil {
		panic("capnp parsing error")
	}
	if data.HasInstOffsets() {
		instOffsets, err := data.InstOffsets()
		if err != nil {
			panic("offset section missing")
		}
		offs, err := instOffsets.Offset()
		if err != nil {
			panic("offset array missing")
		}
		for i := 0; i < offs.Len(); i++ {
			ety = append(ety, int(offs.At(i)))
		}
	}
	if data.HasFuncStarts() {
		funcStarts, err := data.FuncStarts()
		if err != nil {
			panic("func section missing")
		}
		funcs, err := funcStarts.Func()
		if err != nil {
			panic("func array missing")
		}
		for i := 0; i < funcs.Len(); i++ {
			fnc = append(fnc, int(funcs.At(i)))
		}
	}
	return
}
