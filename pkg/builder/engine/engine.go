/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyConvert "github.com/zclconf/go-cty/cty/convert"
)

// Engine contains the conditions of rules and comments positions
type Engine struct {
}

// ExpToString converts an expression into a string
func (e *Engine) ExpToString(ctx context.Context, expr hclsyntax.Expression) (string, error) {
	contextLogger := logger.FromContext(ctx)
	switch t := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		return e.expToStringLiteralValue(t)
	case *hclsyntax.TemplateExpr:
		return e.expToStringTemplateExpr(ctx, t)
	case *hclsyntax.TemplateWrapExpr:
		return e.ExpToString(ctx, t.Wrapped)
	case *hclsyntax.ParenthesesExpr:
		return e.ExpToString(ctx, t.Expression)
	case *hclsyntax.ObjectConsKeyExpr:
		return e.ExpToString(ctx, t.Wrapped)
	case *hclsyntax.ScopeTraversalExpr:
		return e.expToStringScopeTraversal(t), nil
	case *hclsyntax.IndexExpr:
		return e.indexExprToString(ctx, t)
	case *hclsyntax.RelativeTraversalExpr:
		return e.expToStringRelativeTraversal(ctx, t)
	case *hclsyntax.FunctionCallExpr:
		return e.expToStringFunctionCall(ctx, t)
	case *hclsyntax.ConditionalExpr:
		condStr, err := e.ExpToString(ctx, t.Condition)
		if err != nil {
			return "", err
		}
		trueStr, err := e.ExpToString(ctx, t.TrueResult)
		if err != nil {
			return "", err
		}
		falseStr, err := e.ExpToString(ctx, t.FalseResult)
		if err != nil {
			return "", err
		}
		return condStr + " ? " + trueStr + " : " + falseStr, nil
	case *hclsyntax.TupleConsExpr:
		parts := make([]string, 0, len(t.Exprs))
		for _, ex := range t.Exprs {
			s, err := e.ExpToString(ctx, ex)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case *hclsyntax.ObjectConsExpr:
		parts := make([]string, 0, len(t.Items))
		for _, item := range t.Items {
			keyStr, err := e.ExpToString(ctx, item.KeyExpr)
			if err != nil {
				return "", err
			}
			valStr, err := e.ExpToString(ctx, item.ValueExpr)
			if err != nil {
				return "", err
			}
			parts = append(parts, keyStr+": "+valStr)
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	}
	err := fmt.Errorf("can't convert expression %T to string", expr)
	contextLogger.Error().Msg(err.Error())
	return "", err
}

func (e *Engine) expToStringLiteralValue(t *hclsyntax.LiteralValueExpr) (string, error) {
	s, err := ctyConvert.Convert(t.Val, cty.String)
	if err != nil {
		return "", err
	}
	return s.AsString(), nil
}

func (e *Engine) expToStringTemplateExpr(ctx context.Context, t *hclsyntax.TemplateExpr) (string, error) {
	if t.IsStringLiteral() {
		v, err := t.Value(nil)
		if err != nil {
			return "", err
		}
		return v.AsString(), nil
	}
	return e.buildString(ctx, t.Parts)
}

func (e *Engine) expToStringScopeTraversal(t *hclsyntax.ScopeTraversalExpr) string {
	items := evaluateScopeTraversalExpr(t.Traversal)
	return strings.Join(items, ".")
}

func (e *Engine) expToStringRelativeTraversal(ctx context.Context, t *hclsyntax.RelativeTraversalExpr) (string, error) {
	sourceStr, err := e.ExpToString(ctx, t.Source)
	if err != nil {
		return "", err
	}
	if len(t.Traversal) == 0 {
		return sourceStr, nil
	}
	return sourceStr + relativeTraversalToString(t.Traversal), nil
}

func (e *Engine) expToStringFunctionCall(ctx context.Context, t *hclsyntax.FunctionCallExpr) (string, error) {
	args := make([]string, 0, len(t.Args))
	for _, arg := range t.Args {
		s, err := e.ExpToString(ctx, arg)
		if err != nil {
			return "", err
		}
		args = append(args, s)
	}
	return t.Name + "(" + strings.Join(args, ", ") + ")", nil
}

func (e *Engine) buildString(ctx context.Context, parts []hclsyntax.Expression) (string, error) {
	builder := &strings.Builder{}

	for _, part := range parts {
		s, err := e.ExpToString(ctx, part)
		if err != nil {
			return "", err
		}
		builder.WriteString(s)
	}

	s := builder.String()

	builder.Reset()
	builder = nil

	return s, nil
}

func (e *Engine) indexExprToString(ctx context.Context, t *hclsyntax.IndexExpr) (string, error) {
	if t == nil || t.Collection == nil || t.Key == nil {
		return "", fmt.Errorf("invalid IndexExpr: nil collection or key")
	}
	coll, err := e.ExpToString(ctx, t.Collection)
	if err != nil {
		return "", err
	}
	key, err := e.ExpToString(ctx, t.Key)
	if err != nil {
		return "", err
	}
	return coll + "[" + key + "]", nil
}

func evaluateScopeTraversalExpr(t hcl.Traversal) []string {
	items := make([]string, 0)
	for _, part := range t {
		switch tt := part.(type) {
		case hcl.TraverseAttr:
			items = append(items, tt.Name)
		case hcl.TraverseRoot:
			items = append(items, tt.Name)
		case hcl.TraverseIndex:
			switch tt.Key.Type() {
			case cty.Number:
				items = append(items, tt.Key.AsBigFloat().String())
			case cty.String:
				items = append(items, tt.Key.AsString())
			}
		}
	}
	return items
}

// relativeTraversalToString formats a relative traversal (e.g. .attr or [0]) so that
// TraverseAttr becomes ".name" and TraverseIndex becomes "[key]".
func relativeTraversalToString(t hcl.Traversal) string {
	var b strings.Builder
	for _, step := range t {
		switch s := step.(type) {
		case hcl.TraverseAttr:
			b.WriteString(".")
			b.WriteString(s.Name)
		case hcl.TraverseIndex:
			b.WriteString("[")
			switch s.Key.Type() {
			case cty.Number:
				b.WriteString(s.Key.AsBigFloat().String())
			case cty.String:
				b.WriteString(s.Key.AsString())
			}
			b.WriteString("]")
		}
	}
	return b.String()
}
