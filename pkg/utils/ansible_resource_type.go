/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import "strings"

// NormalizeAnsibleResourceType returns the Ansible content name (last segment after ".") from a
// fully qualified collection name (FQCN) or short name. Used so that rego rules can output
// either "community.aws.ec2_instance" or "ec2_instance" and we consistently expose "ec2_instance".
// If resourceType has no ".", it is returned unchanged.
func NormalizeAnsibleResourceType(resourceType string) string {
	if idx := strings.LastIndex(resourceType, "."); idx != -1 {
		return resourceType[idx+1:]
	}
	return resourceType
}
