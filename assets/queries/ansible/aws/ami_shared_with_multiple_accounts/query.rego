package Cx

import data.generic.ansible as ansLib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	modules := {"amazon.aws.ec2_ami", "ec2_ami"}
	ec2Ami := task[modules[m]]
	ansLib.checkState(ec2Ami)

	amiIsShared(ec2Ami.launch_permissions)

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(ec2Ami, "image_id", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}.launch_permissions", [task.name, modules[m]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_ami.launch_permissions just allows one user to launch the AMI",
		"keyActualValue": "ec2_ami.launch_permissions allows more than one user to launch the AMI",
	}
}

amiIsShared(attribute) = allow {
	attribute.group_names
	allow = true
}

amiIsShared(attribute) = allow {
	count(attribute.user_ids) > 1
	allow = true
}
