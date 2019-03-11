package revdb

import (
	"fmt"
	"testing"
)

func TestBoltOpen(t *testing.T) {
	blt := NewboltDB("./", "test1", "tstDB")
	defer blt.db.Close()
	if blt == nil {
		t.Errorf("BoltOpen:")
	}
}

func TestBoltReadWrite(t *testing.T) {
	blt := NewboltDB("./", "test1", "tstDB")
	defer blt.db.Close()
	if blt == nil {
		t.Errorf("BoltOpen:")
	}

	if data, err := blt.ReadDB("123.13.1.4"); err == nil {
		if len(data) != 0 {
			t.Error("Negative test case failed")
		}
	} else {
		t.Error("Negative test case failed:ERROR")
	}

	if _, err := blt.WriteDB("127.21.21.1",
		[]string{"abc.com", "xyz.com", "rwe.cas"}); err != nil {
		fmt.Println(err)
		t.Error("Write Failed")
	}

	if domains, err := blt.ReadDB("127.21.21.1"); err == nil {
		if len(domains) != 3 {
			t.Errorf("Invalid read: %s", domains)
			return
		}
	} else {
		t.Error("Positive read case failed")
	}

	if _, err := blt.WriteDB("127.21.21.1",
		[]string{"123.com", "abc.com", "xyz.com", "rwe.cas"}); err != nil {
		fmt.Println(err)
		t.Error("Write Failed")
	}

	if domains, err := blt.ReadDB("127.21.21.1"); err == nil {
		if len(domains) != 4 {
			t.Errorf("Invalid read: %s", domains)
			return
		}
	} else {
		t.Error("Positive read case failed")
	}
}
