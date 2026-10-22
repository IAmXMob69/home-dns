package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestURLs(t *testing.T) {
	got := URLs("# c\nhttps://a\r\n  https://b  \nhttps://a\nftp://x\nhttp://c")
	if want := []string{"https://a", "https://b", "http://c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	dbp := filepath.Join(dir, "g.db")
	db, _ := sql.Open("sqlite", dbp)
	if _, err := db.Exec(`CREATE TABLE adlist (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT UNIQUE NOT NULL, enabled BOOLEAN NOT NULL DEFAULT 1, comment TEXT);
INSERT INTO adlist(address,enabled) VALUES('https://a',0);`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	lists := filepath.Join(dir, "lists.txt")
	os.WriteFile(lists, []byte("https://a\nhttps://b\nhttps://c\n"), 0o600)
	var out bytes.Buffer
	if err := run(lists, dbp, &out); err != nil {
		t.Fatal(err)
	}
	want := "lists in file: 3\nnewly inserted: 2\nadlists now: 2 enabled / 3 total\nRun: docker exec pihole pihole -g\n"
	if out.String() != want {
		t.Fatalf("%q", out.String())
	}
}
