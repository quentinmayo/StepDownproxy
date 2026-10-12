package stepdown

import rego.v1

default allow := false

# Exact routes prevent a read grant from becoming access to unrelated assets.
# Replace the identity, owner, repository, and methods for your deployment.
allow if {
    input.principal == "demo-reader"
    input.service == "github"
    input.method in {"GET", "HEAD"}
    input.path == "/repos/example/project/issues"
    input.body == null
    every name, values in input.query {
        name in {"state", "per_page", "page"}
        count(values) == 1
    }
}

# Example narrowly scoped write rule; no configured client has this identity.
allow if {
    input.principal == "issue-writer"
    input.service == "github"
    input.method == "POST"
    input.path == "/repos/example/project/issues"
    count(input.query) == 0
    is_object(input.body)
    is_string(input.body.title)
    count(input.body.title) > 0
    count(input.body.title) <= 200
    count(object.keys(input.body) - {"title", "body"}) == 0
    is_string(object.get(input.body, "body", ""))
}
