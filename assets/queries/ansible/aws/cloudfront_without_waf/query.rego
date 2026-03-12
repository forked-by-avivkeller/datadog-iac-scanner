package Cx

import data.generic.ansible as ansLib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	modules := {"community.aws.cloudfront_distribution", "cloudfront_distribution"}
	cloudfront := task[modules[m]]
	ansLib.checkState(cloudfront)

	not cloudfront.web_acl_id

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(cloudfront, "distribution_id", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, modules[m]]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudfront_distribution.web_acl_id should be defined",
		"keyActualValue": "cloudfront_distribution.web_acl_id is undefined",
	}
}
