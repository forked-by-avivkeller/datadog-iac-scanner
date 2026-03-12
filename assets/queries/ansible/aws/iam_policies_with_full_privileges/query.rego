package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	modules := {"community.aws.iam_managed_policy", "iam_managed_policy"}
	iamPolicy := task[modules[m]]
	ans_lib.checkState(iamPolicy)

	st := common_lib.get_statement(common_lib.get_policy(iamPolicy.policy))
	statement := st[_]

	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.Resource, "*")
	common_lib.equalsOrInArray(statement.Action, "*")

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(iamPolicy, "name", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}.policy", [task.name, modules[m]]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "iam_managed_policy.policy.Statement.Action should not contain '*'",
		"keyActualValue": "iam_managed_policy.policy.Statement.Action contains '*'",
		"searchLine": common_lib.build_search_line(["playbooks", t, modules[m], "policy"], []),
	}
}
