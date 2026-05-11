package sniff

import "testing"

func TestFormat(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"umd-canonical",
			`(function(root,factory){if(typeof define==='function'&&define.amd){define([],factory)}else if(typeof exports==='object'){module.exports=factory()}else{root.Foo=factory()}})(this,function(){return{}});`,
			UMD,
		},
		{
			"umd-minified",
			`!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):(e=e||self).htmx=t()}(this,function(){});`,
			UMD,
		},
		{
			"system",
			`System.register([],function(e){return{execute:function(){}}});`,
			SystemJS,
		},
		{
			"amd-bare",
			`define(['dep'],function(d){return{}});`,
			AMD,
		},
		{
			"esm-export",
			`export const x = 1; export default function(){};`,
			ESM,
		},
		{
			"esm-import",
			`import {foo} from './bar.js'; foo();`,
			ESM,
		},
		{
			"esm-export-from",
			`export * from './x.js';`,
			ESM,
		},
		{
			"cjs",
			`const x = require('./x'); module.exports = {x};`,
			CJS,
		},
		{
			"cjs-exports-dot",
			`exports.foo = 1; exports.bar = 2;`,
			CJS,
		},
		{
			"cjs-tsc-marker",
			`Object.defineProperty(exports,"__esModule",{value:true}); exports.foo=1;`,
			CJS,
		},
		{
			"iife",
			`(function(){"use strict";var x=1;window.Foo=x;})();`,
			IIFE,
		},
		{
			"iife-arrow",
			`(()=>{var x=1;window.Foo=x;})();`,
			IIFE,
		},
		{
			"iife-bang",
			`!function(){var x=1}();`,
			IIFE,
		},
		{
			"iife-htmx-style",
			`var htmx=function(){"use strict";return{}}();`,
			IIFE,
		},
		{
			"unknown-plain",
			`var x = 1; console.log(x);`,
			Unknown,
		},
		{
			"empty",
			``,
			Unknown,
		},
		{
			"esm-marker-in-string-not-detected",
			`var s = "export default x"; console.log(s);`,
			Unknown,
		},
		{
			"esm-marker-in-comment-not-detected",
			`/* export default x */ var s = 1;`,
			Unknown,
		},
		{
			"umd-with-esm-string-inside",
			`(function(r,f){if(typeof define==='function'&&define.amd){define(f)}else{r.x=f()}})(this,function(){var s="import foo";return s});`,
			UMD,
		},
		{
			"importScripts-not-esm",
			`importScripts('worker.js'); var x=1;`,
			Unknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Format([]byte(tc.src)); got != tc.want {
				t.Errorf("Format() = %q, want %q\nsrc: %s", got, tc.want, tc.src)
			}
		})
	}
}

func TestStripStringsAndComments(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`var x = "hello"; // tail`, `var x = ""; `},
		{`/* block */ x`, ` x`},
		{`'a' + "b" + ` + "`c`", `'' + "" + ` + "``"},
		{`"esc\"ape"`, `""`},
		{`/regex/g.test(x)`, `/regex/g.test(x)`},
		{"// line1\ncode\n// line2", "\ncode\n"},
	}
	for _, tc := range cases {
		got := string(stripStringsAndComments([]byte(tc.in)))
		if got != tc.want {
			t.Errorf("strip(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
