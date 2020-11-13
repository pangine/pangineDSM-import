package ghidracall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// GoDir uses `go list` to get the location of present package
func GoDir() (dir string) {
	golist := exec.Command("go", "list", "-f", "{{.Dir}}", "github.com/pangine/pangineDSM-import/ghidraCall")
	res, errin := golist.Output()
	if errin != nil {
		panic(errin)
	}
	dir = string(res)
	//fmt.Println(dir)
	return filepath.Join(dir, "..")
}

// HeadlessLoc reads the path of Ghidra HeadlessAnalyzer in ghrdraScript/headlessLoc.txt
func HeadlessLoc(file string) (loc string) {
	bin, finerr := os.Open(file)
	if finerr != nil {
		fmt.Printf("\t%s does not exist\n", file)
		return
	}
	defer bin.Close()

	lines := bufio.NewScanner(bin)
	for lines.Scan() {
		loc = lines.Text()
		return
	}
	return
}
