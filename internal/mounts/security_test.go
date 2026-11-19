package mounts

import (
	"strings"
	"testing"
)

func TestRejectsInvalidDecodedMountFields(t *testing.T) {
	for _, input := range []string{
		`100 1 -1:0 / / rw - overlay overlay rw,lowerdir=/lower`,
		`100 1 0:-1 / / rw - overlay overlay rw,lowerdir=/lower`,
		`100 1 0:1 relative / rw - overlay overlay rw,lowerdir=/lower`,
		`100 1 0:1 relative / rw - nsfs nsfs rw`,
		`100 1 0:1 net:[not-an-inode] / rw - nsfs nsfs rw`,
		`100 1 0:1 / /\000hidden rw - overlay overlay rw,lowerdir=/lower`,
		`100 1 0:1 / / rw - overlay source\000name rw,lowerdir=/lower`,
		`100 1 0:1 / / rw - overlay overlay rw,lowerdir=/lower\377`,
	} {
		if _, err := Parse(strings.NewReader(input + "\n")); err == nil {
			t.Errorf("accepted malformed decoded mount metadata: %s", input)
		}
	}
}

func TestKernelNamespaceRootIsPreserved(t *testing.T) {
	table, err := Parse(strings.NewReader("100 1 0:4 net:[4026533508] /run/netns/example rw - nsfs nsfs rw\n"))
	if err != nil || len(table) != 1 || table[0].Root != "net:[4026533508]" {
		t.Fatalf("kernel nsfs root must remain supported: %+v %v", table, err)
	}
}

func TestEscapedOptionDelimitersCannotIntroduceFlags(t *testing.T) {
	input := `100 1 0:1 / / rw - overlay overlay rw,lowerdir=/base:/lower\134\054userxattr,upperdir=/upper\134\054part` + "\n"
	table, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	e := table[0]
	if len(e.SuperOptions) != 3 || e.SuperValue("upperdir") != "/upper,part" {
		t.Fatalf("escaped comma was treated as a delimiter: %#v", e.SuperOptions)
	}
	lowers := e.LowerDirs()
	if len(lowers) != 2 || lowers[0] != "/base" || lowers[1] != "/lower,userxattr" {
		t.Fatalf("wrong decoded layer addresses: %#v", lowers)
	}
	for _, option := range e.SuperOptions {
		if option == "userxattr" {
			t.Fatal("a path component became an attribute-authority flag")
		}
	}
}
