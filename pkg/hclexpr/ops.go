/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package hclexpr

import (
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// BinaryOpSymbol returns the HCL operator symbol for a binary operation (e.g. "+", "==").
func BinaryOpSymbol(op *hclsyntax.Operation) string {
	if op == nil {
		return "?"
	}
	switch op {
	case hclsyntax.OpLogicalOr:
		return "||"
	case hclsyntax.OpLogicalAnd:
		return "&&"
	case hclsyntax.OpEqual:
		return "=="
	case hclsyntax.OpNotEqual:
		return "!="
	case hclsyntax.OpGreaterThan:
		return ">"
	case hclsyntax.OpGreaterThanOrEqual:
		return ">="
	case hclsyntax.OpLessThan:
		return "<"
	case hclsyntax.OpLessThanOrEqual:
		return "<="
	case hclsyntax.OpAdd:
		return "+"
	case hclsyntax.OpSubtract:
		return "-"
	case hclsyntax.OpMultiply:
		return "*"
	case hclsyntax.OpDivide:
		return "/"
	case hclsyntax.OpModulo:
		return "%"
	default:
		return "?"
	}
}

// UnaryOpSymbol returns the HCL operator symbol for a unary operation (e.g. "-", "!").
func UnaryOpSymbol(op *hclsyntax.Operation) string {
	if op == nil {
		return "?"
	}
	switch op {
	case hclsyntax.OpLogicalNot:
		return "!"
	case hclsyntax.OpNegate:
		return "-"
	default:
		return "?"
	}
}
