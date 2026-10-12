package stepdown_test

import rego.v1

base := {"principal":"demo-reader", "service":"github", "method":"GET", "path":"/repos/example/project/issues", "query":{}, "body":null}

test_reader if { data.stepdown.allow with input as base }
test_delete_denied if { not data.stepdown.allow with input as object.union(base,{"method":"DELETE"}) }
test_other_repo_denied if { not data.stepdown.allow with input as object.union(base,{"path":"/repos/example/other/issues"}) }
test_spoofed_identity_denied if { not data.stepdown.allow with input as object.union(base,{"principal":"admin"}) }
test_query_denied if { not data.stepdown.allow with input as object.union(base,{"query":{"redirect":["https://example.com"]}}) }
test_duplicate_query_denied if { not data.stepdown.allow with input as object.union(base,{"query":{"state":["open","closed"]}}) }
test_scoped_write if { data.stepdown.allow with input as object.union(base,{"principal":"issue-writer","method":"POST","body":{"title":"New issue"}}) }
test_write_extra_fields_denied if { not data.stepdown.allow with input as object.union(base,{"principal":"issue-writer","method":"POST","body":{"title":"New issue","assignees":["admin"]}}) }
