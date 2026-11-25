package lab.deploy_test

import data.lab.deploy
import rego.v1

allowed := {
	"container": {"user": "10001", "base_image": "python:3.12-slim-bookworm", "healthcheck": true},
	"dependencies": ["fastapi==0.165.0", "uvicorn[standard]==0.34.0"],
}

denied := {
	"container": {"user": "root", "base_image": "python:latest", "healthcheck": false},
	"dependencies": ["fastapi"],
}

test_allowed_config_has_no_denials if {
	count(deploy.deny) == 0 with input as allowed
}

test_denied_config_is_rejected if {
	count(deploy.deny) == 3 with input as denied
}

test_missing_healthcheck_only_warns if {
	count(deploy.warn) == 1 with input as denied
	count(deploy.warn) == 0 with input as allowed
}
