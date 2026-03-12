package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

modules := {"amazon.aws.ec2_instance", "community.aws.ec2_instance", "community.aws.autoscaling_launch_config", "community.aws.ec2_lc"}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	resource := task[modules[m]]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	not common_lib.valid_key(resource, "metadata_options")

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(resource, "name", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, modules[m]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, modules[m]], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s.metadata_options' should be defined with 'http_tokens' field set to 'required'", [modules[m]]),
		"keyActualValue": sprintf("'%s.metadata_options' is not defined", [modules[m]]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	resource := task[modules[m]]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	common_lib.valid_key(resource, "metadata_options")
	common_lib.valid_key(resource.metadata_options, "http_tokens")
	not resource.metadata_options.http_tokens == "required"

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(resource, "name", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata_options.http_tokens", [task.name, modules[m]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, modules[m], "metadata_options", "http_tokens"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.metadata_options.http_tokens' should be defined to 'required'", [modules[m]]),
		"keyActualValue": sprintf("'%s.metadata_options.http_tokens' is not defined to 'required'", [modules[m]]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	resource := task[modules[m]]
	ansLib.checkState(resource)

	is_metadata_service_enabled(resource)

	common_lib.valid_key(resource, "metadata_options")
	not common_lib.valid_key(resource.metadata_options, "http_tokens")

	result := {
		"documentId": id,
		"resourceType": modules[m],
		"resourceName": object.get(resource, "name", task.name),
		"searchKey": sprintf("name={{%s}}.{{%s}}.metadata_options", [task.name, modules[m]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, modules[m], "metadata_options"], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s.metadata_options.http_tokens' should be defined to 'required'", [modules[m]]),
		"keyActualValue": sprintf("'%s.metadata_options.http_tokens' is not defined", [modules[m]]),
	}
}

is_metadata_service_enabled(resource) {
	common_lib.valid_key(resource, "metadata_options")
	common_lib.valid_key(resource.metadata_options, "http_endpoint")
	resource.metadata_options.http_endpoint == "enabled"
}

is_metadata_service_enabled(resource) {
	not common_lib.valid_key(resource, "metadata_options")
}

is_metadata_service_enabled(resource) {
	common_lib.valid_key(resource, "metadata_options")
	not common_lib.valid_key(resource.metadata_options, "http_endpoint")
}
