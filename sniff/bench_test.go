package sniff

import (
	"strings"
	"testing"
)

func BenchmarkFormatIIFE_64KB(b *testing.B) {
	src := []byte("var x=function(){\"use strict\";" + strings.Repeat("var n=1;", 8000) + "return{}}();")
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for b.Loop() {
		_ = Format(src)
	}
}

func BenchmarkFormatUMD(b *testing.B) {
	src := []byte("(function(r,f){if(typeof define==='function'&&define.amd){define([],f)}else if(typeof exports==='object'){module.exports=f()}else{r.X=f()}})(this,function(){return{}});")
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for b.Loop() {
		_ = Format(src)
	}
}

func BenchmarkFormatESM(b *testing.B) {
	src := []byte("import{a,b}from'./m';export const x=1;export default function(){};")
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for b.Loop() {
		_ = Format(src)
	}
}

func BenchmarkStripStringsAndComments(b *testing.B) {
	src := []byte(`var x = "hello \"world\""; /* block */ var y = 'a'; // tail
var z = ` + "`tpl ${x}`" + `; var w = /regex/g;`)
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for b.Loop() {
		_ = stripStringsAndComments(src)
	}
}
