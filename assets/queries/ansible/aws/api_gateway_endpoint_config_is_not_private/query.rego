package Cx

import data.generic.ansible as ansLib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	modules := {"community.aws.aws_api_gateway", "aws_api_gateway"}
	apiGateway := task[modules[m]]
	ansLib.checkState(apiGateway)

	apiGateway.endpoint_type != "PRIVATE"

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(apiGateway, "name", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}.endpoint_type", [task.name, modules[m]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'aws_api_gateway.endpoint_type' should be set to 'PRIVATE'",
		"keyActualValue": "'aws_api_gateway.endpoint_type' is not 'PRIVATE'",
	}
}
