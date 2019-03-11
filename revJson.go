package main

import (
	"log"

	"github.com/antonholmquist/jason"
)

//Wrapper API for JSON parsing

type revJson struct {
	root *jason.Object
}

func NewRevJson(buff []byte) *revJson {
	js, err := jason.NewObjectFromBytes(buff)
	if err != nil {
		log.Println(err)
		return nil
	}
	return &revJson{
		root: js,
	}
}
func (js *revJson) getValStr(key string) (string, error) {
	return js.root.GetString(key)
}

func (js *revJson) getValStrSlice(key string) ([]string, error) {
	return js.root.GetStringArray(key)
}

func (js *revJson) compareValStr(key string, val string) (int, error) {
	if v, err := js.getValStr(key); err != nil {
		if v == val {
			return 0, nil
		}
	} else {
		log.Panicln(err)
	}
	return -1, nil
}
