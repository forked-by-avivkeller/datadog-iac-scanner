/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeAnsibleResourceType(t *testing.T) {
	tests := []struct {
		name        string
		resourceType string
		want        string
	}{
		{
			name:        "FQCN community.aws returns last segment",
			resourceType: "community.aws.ec2_instance",
			want:        "ec2_instance",
		},
		{
			name:        "FQCN ansible.builtin returns last segment",
			resourceType: "ansible.builtin.user",
			want:        "user",
		},
		{
			name:        "FQCN azure.azcollection returns last segment",
			resourceType: "azure.azcollection.azure_rm_aks",
			want:        "azure_rm_aks",
		},
		{
			name:        "FQCN google.cloud returns last segment",
			resourceType: "google.cloud.gcp_compute_firewall",
			want:        "gcp_compute_firewall",
		},
		{
			name:        "short name with no dot is unchanged",
			resourceType: "ec2_instance",
			want:        "ec2_instance",
		},
		{
			name:        "conceptual type with no dot is unchanged",
			resourceType: "ansible_config",
			want:        "ansible_config",
		},
		{
			name:        "ansible_playbook unchanged",
			resourceType: "ansible_playbook",
			want:        "ansible_playbook",
		},
		{
			name:        "ansible_task unchanged",
			resourceType: "ansible_task",
			want:        "ansible_task",
		},
		{
			name:        "community.aws.aws_kms to aws_kms",
			resourceType: "community.aws.aws_kms",
			want:        "aws_kms",
		},
		{
			name:        "installer module FQCN to short name",
			resourceType: "community.general.apt",
			want:        "apt",
		},
		{
			name:        "empty string unchanged",
			resourceType: "",
			want:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeAnsibleResourceType(tt.resourceType)
			require.Equal(t, tt.want, got)
		})
	}
}
