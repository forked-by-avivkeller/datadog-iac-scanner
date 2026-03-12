package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	modules := {"community.aws.cloudwatchlogs_log_group", "cloudwatchlogs_log_group"}
	logGroup := task[modules[m]]
	ansLib.checkState(logGroup)

	not common_lib.valid_key(logGroup, "log_group_name")

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(logGroup, "log_group_name", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, modules[m]]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "cloudwatchlogs_log_grouptracing_enabled should contain log_group_name",
		"keyActualValue": "cloudwatchlogs_log_group does not contain log_group_name defined",
	}
}
