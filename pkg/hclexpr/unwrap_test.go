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

func TestUnwrap(t *testing.T) {
	t.Run("TemplateWrapExpr", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`"${var.x}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got := Unwrap(expr)
		if _, ok := got.(*hclsyntax.ScopeTraversalExpr); !ok {
			t.Errorf("Unwrap(TemplateWrapExpr) = %T, want *hclsyntax.ScopeTraversalExpr", got)
		}
	})

	t.Run("ParenthesesExpr", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("(var.x)"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got := Unwrap(expr)
		if _, ok := got.(*hclsyntax.ScopeTraversalExpr); !ok {
			t.Errorf("Unwrap(ParenthesesExpr) = %T, want *hclsyntax.ScopeTraversalExpr", got)
		}
	})

	t.Run("nested_wrappers", func(t *testing.T) {
		// "${(var.x)}" parses as TemplateWrapExpr wrapping ParenthesesExpr wrapping ScopeTraversalExpr
		expr, diags := hclsyntax.ParseExpression([]byte(`"${(var.x)}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got := Unwrap(expr)
		if _, ok := got.(*hclsyntax.ScopeTraversalExpr); !ok {
			t.Errorf("Unwrap(TemplateWrap(Parentheses(ScopeTraversal))) = %T, want *hclsyntax.ScopeTraversalExpr", got)
		}
	})

	t.Run("non_wrapper_unchanged", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("var.x"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		got := Unwrap(expr)
		if got != expr {
			t.Errorf("Unwrap(ScopeTraversalExpr) should return same expr, got %T", got)
		}
	})
}
