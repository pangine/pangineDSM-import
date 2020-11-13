@0xea5a513cb1666fde;

using Go = import "/go.capnp";
$Go.package("pangine");
$Go.import("github.com/pangine");

struct AnalysisRst $Go.doc("record all necessary fields for analysis") {
  instOffsets @0 : InstOffset;
  funcStarts @1 : FuncStart;
}

struct InstOffset $Go.doc("offsets that can be considered as an instruction") {
  offset @0 : List(Int64);
}

struct FuncStart $Go.doc("offsets that represent the start of a function") {
  func @0 : List(Int64);
}
