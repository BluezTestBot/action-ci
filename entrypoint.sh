#!/usr/bin/env bash

echo "Workflow:   $GITHUB_WORKFLOW"
echo "Action:     $GITHUB_ACTION"
echo "Actor:      $GITHUB_ACTOR"
echo "Repository: $GITHUB_REPOSITORY"
echo "Event-name: $GITHUB_EVENT_NAME"
echo "Event-path: $GITHUB_EVENT_PATH"
echo "Workspace:  $GITHUB_WORKSPACE"
echo "SHA:        $GITHUB_SHA"
echo "REF:        $GITHUB_REF"
echo "HEAD-REF:   $GITHUB_HEAD_REF"
echo "BASE-REF:   $GITHUB_BASE_REF"
echo "PWD:        $(pwd)"

if [[ -z $GITHUB_TOKEN ]]
then
	echo "Set GITHUB_TOKEN environment variable"
	exit 1
fi

# Get PR number from GITHUB_REF (refs/pull/#/merge)
PR=${GITHUB_REF#"refs/pull/"}
PR=${PR%"/merge"}

/run-ci.py -c /config.ini -p $PR -r $GITHUB_REPOSITORY -v
