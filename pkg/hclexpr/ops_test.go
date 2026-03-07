/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package hclexpr

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func parseExpr(t *testing.T, src string) hclsyntax.Expression {
	t.Helper()
	expr, diags := hclsyntax.ParseExpression([]byte(src), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse %q failed: %v", src, diags)
	}
	return expr
}

func TestBinaryOpSymbol(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{"1 + 2", "+"},
		{"1 - 2", "-"},
		{"1 * 2", "*"},
		{"1 / 2", "/"},
		{"1 % 2", "%"},
		{"1 == 2", "=="},
		{"1 != 2", "!="},
		{"1 > 2", ">"},
		{"1 >= 2", ">="},
		{"1 < 2", "<"},
		{"1 <= 2", "<="},
		{"true || false", "||"},
		{"true && false", "&&"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			expr := parseExpr(t, tt.src)
			bin, ok := expr.(*hclsyntax.BinaryOpExpr)
			if !ok {
				t.Fatalf("expected *BinaryOpExpr, got %T", expr)
			}
			got := BinaryOpSymbol(bin.Op)
			if got != tt.want {
				t.Errorf("BinaryOpSymbol = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnaryOpSymbol(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{"-1", "-"},
		{"!true", "!"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			expr := parseExpr(t, tt.src)
			un, ok := expr.(*hclsyntax.UnaryOpExpr)
			if !ok {
				t.Fatalf("expected *UnaryOpExpr, got %T", expr)
			}
			got := UnaryOpSymbol(un.Op)
			if got != tt.want {
				t.Errorf("UnaryOpSymbol = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBinaryOpSymbol_nil(t *testing.T) {
	if got := BinaryOpSymbol(nil); got != "?" {
		t.Errorf("BinaryOpSymbol(nil) = %q, want ?", got)
	}
}

func TestUnaryOpSymbol_nil(t *testing.T) {
	if got := UnaryOpSymbol(nil); got != "?" {
		t.Errorf("UnaryOpSymbol(nil) = %q, want ?", got)
	}
}
