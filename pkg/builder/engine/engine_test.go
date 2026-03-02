/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// TestEngine_BuildString tests the functions [buildString()] and all the methods called by them
func TestEngine_BuildString(t *testing.T) {
	type args struct {
		parts []hclsyntax.Expression
	}
	type fields struct {
		Engine *Engine
	}
	tests := []struct {
		name    string
		args    args
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "build_string",
			fields: fields{
				Engine: &Engine{},
			},
			args: args{
				parts: []hclsyntax.Expression{},
			},
			want:    "",
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fields.Engine.buildString(ctx, tt.args.parts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpToString_IndexExpr(t *testing.T) {
	expr, diags := hclsyntax.ParseExpression([]byte("var.list[var.i]"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("parse failed: %v", diags)
	}
	indexExpr, ok := expr.(*hclsyntax.IndexExpr)
	if !ok {
		t.Fatalf("expected *hclsyntax.IndexExpr, got %T", expr)
	}

	e := &Engine{}
	ctx := context.Background()

	t.Run("via ExpToString", func(t *testing.T) {
		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString(IndexExpr): %v", err)
		}
		if want := "var.list[var.i]"; got != want {
			t.Errorf("ExpToString(IndexExpr) = %q, want %q", got, want)
		}
	})

	t.Run("via indexExprToString", func(t *testing.T) {
		got, err := e.indexExprToString(ctx, indexExpr)
		if err != nil {
			t.Fatalf("indexExprToString: %v", err)
		}
		if want := "var.list[var.i]"; got != want {
			t.Errorf("indexExprToString() = %q, want %q", got, want)
		}
	})
}

func TestExpToString_RelativeTraversalExpr(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("relative_traversal_after_index", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i].name"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "list[var.i].name"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("relative_traversal_multi_step", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i].a.b"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "list[var.i].a.b"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("relative_traversal_with_index_step", func(t *testing.T) {
		// e.g. list[var.i][0] -> RelativeTraversalExpr(IndexExpr, [TraverseIndex(0)])
		expr, diags := hclsyntax.ParseExpression([]byte("list[var.i][0]"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		got, err := e.ExpToString(ctx, expr)
		if err != nil {
			t.Fatalf("ExpToString error: %v", err)
		}
		if want := "list[var.i][0]"; got != want {
			t.Errorf("ExpToString = %q, want %q", got, want)
		}
	})

	t.Run("unsupported_source_propagates_error", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("tostring(var.x).attr"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		_, err := e.ExpToString(ctx, expr)
		if err == nil {
			t.Error("ExpToString should return error for unsupported source type")
		}
	})
}

func TestExpToString_IndexExpr_edgeCases(t *testing.T) {
	e := &Engine{}
	ctx := context.Background()

	t.Run("nil IndexExpr", func(t *testing.T) {
		var nilIndex *hclsyntax.IndexExpr
		_, err := e.indexExprToString(ctx, nilIndex)
		if err == nil {
			t.Error("indexExprToString(nil) should return error")
		}
	})
}
