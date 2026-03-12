package Cx

import data.generic.ansible as ansLib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	modules := {"community.aws.iam_policy", "iam_policy"}
	iamPolicy := task[modules[m]]
	ansLib.checkState(iamPolicy)

	lower(iamPolicy.iam_type) == "user"

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(iamPolicy, "policy_name", object.get(iamPolicy, "iam_name", task.name)),
		"searchKey": sprintf("name={{%s}}.{{%s}}.iam_type", [task.name, modules[m]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "iam_policy.iam_type should be configured with group or role",
		"keyActualValue": "iam_policy.iam_type is configured with user",
	}
}
