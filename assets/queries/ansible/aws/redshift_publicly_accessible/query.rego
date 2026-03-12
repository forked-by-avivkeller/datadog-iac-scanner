package Cx

import data.generic.ansible as ansLib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	modules := ["redshift", "community.aws.redshift"]
	redshift := task[modules[m]]
	ansLib.isAnsibleTrue(redshift.publicly_accessible)

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(redshift, "identifier", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}.publicly_accessible", [task.name, modules[m]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "redshift.publicly_accessible should be set to false",
		"keyActualValue": "redshift.publicly_accessible is true",
	}
}
