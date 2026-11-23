package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestClientCommandUsesPrivacySafeLogging(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), `"log"`) || strings.Contains(string(source), "log.") ||
		strings.Contains(string(source), "fmt.Print") || strings.Contains(string(source), "os.Stdout") ||
		strings.Contains(string(source), "os.Stderr") {
		t.Fatal("client command bypasses centralized privacy logging")
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "main.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "clientcore" {
			return true
		}
		switch selector.Sel.Name {
		case "LogState", "LogRateLimitedEvent", "LogOperationalFailure", "FatalOperationalFailure":
			if len(call.Args) < 2 {
				t.Errorf("%s called without fixed component and event", selector.Sel.Name)
				return true
			}
			for index := 0; index < 2; index++ {
				literal, ok := call.Args[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Errorf("%s uses a non-constant logging label", selector.Sel.Name)
				}
			}
		}
		return true
	})
}
