package main

import (
	"os"

	"github.com/go-acme/lego/v4/log"

	"github.com/andrewz1/makecert/xacme"
)

const (
	defConf = "makecert.toml"
)

func main() {
	var conf string
	switch {
	case len(os.Args) < 2:
		conf = defConf
	case len(os.Args) == 2:
		conf = os.Args[1]
	case len(os.Args) > 2:
		log.Fatalf("Usage: %s [%s]", os.Args[0], defConf)
	}
	var err error
	if err = xacme.Init(conf); err != nil {
		log.Fatal(err)
	}
	if err = xacme.Obtain(); err != nil {
		log.Fatal(err)
	}
	if err = xacme.Save(); err != nil {
		log.Fatal(err)
	}
}
