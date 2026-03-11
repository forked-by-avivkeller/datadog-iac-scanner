/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package hclexpr

import (
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Unwrap returns the inner expression for wrapper types (TemplateWrapExpr,
// ParenthesesExpr, ObjectConsKeyExpr). For other expression types, returns expr unchanged.
// Callers can use this before their own type switch so wrapper handling is centralized.
func Unwrap(expr hclsyntax.Expression) hclsyntax.Expression {
	switch e := expr.(type) {
	case *hclsyntax.TemplateWrapExpr:
		return Unwrap(e.Wrapped)
	case *hclsyntax.ParenthesesExpr:
		return Unwrap(e.Expression)
	case *hclsyntax.ObjectConsKeyExpr:
		return Unwrap(e.Wrapped)
	default:
		return expr
	}
}
