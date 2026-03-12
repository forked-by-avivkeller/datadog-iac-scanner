package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

modules := {"community.aws.iam_managed_policy", "iam_managed_policy"}

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
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
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement.Resource' and 'policy.Statement.Action' should no be equal to '*'",
		"keyActualValue": "'policy.Statement.Resource' and 'policy.Statement.Action' are equal to '*'",
		"searchLine": common_lib.build_search_line(["playbooks", t, modules[m], "policy"], []),
	}
}
