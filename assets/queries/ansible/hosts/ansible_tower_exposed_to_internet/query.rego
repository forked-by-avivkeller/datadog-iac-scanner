package Cx

import data.generic.common as common_lib

CxPolicy[result] {
	doc := input.document[id].all
	doc.children.tower.hosts[ip]

    not common_lib.isPrivateIP(ip)

	result := {
		"documentId": input.document[id].id,
		"hostname": "tower",
		"resourceName": "tower",
		"resourceType": "ansible_inventory",
		"searchKey": "all.children.tower.hosts",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Ansible Tower IP should be private",
		"keyActualValue": "Ansible Tower IP is public",
	}
}
