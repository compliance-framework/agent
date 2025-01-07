# METADATA
# title: Stuff
# description: Verify we're doing stuff

package compliance_framework.local_ssh.deny_password_auth

import future.keywords.in

tasks := [
    {
        "title": "Task1",
        "description": "Do the thing",
        "activities": [
            {
                "title": "Activity1",
                "description": "Do the first thing",
                "type": "test",
                "steps": [
                    "Step 1",
                    "Step 2",
                    "Step 3",
                ],
                "tools": ["Tool 1", "Tool 2"]
            },
            {
                "title": "Activity2",
                "description": "Do the next thing",
                "type": "test",
                "steps": [
                    "Step a",
                    "Step b",
                    "Step c",
                ],
                "tools": ["Tool 1", "Tool 2"]
            }
        ]
    }
]

risks := [
    {
        "title": "Risk 1",
        "description": "Risky business",
        "statement": "We could be at risk",
        "links": [
            {
                "text": "stuff",
                "href": "https://attack.mitre.org/techniques/T123/"
            },
        ],
    },
    {
        "title": "Risk 2",
        "description": "Even riskier business",
        "statement": "You should be worried",
        "links": [
            {
                "text": "stuff",
                "href": "https://attack.mitre.org/techniques/T124/"
            },
        ],
    }
]

violation[
    {
        "title": "Violation 1",
        "description": "You have been violated.",
        "remarks": "Migrate to not being violated",
        "control-implementations": [
            "AC-1",
            "AC-2",
        ]
    }
] {
	"yes" in input.violated
}
