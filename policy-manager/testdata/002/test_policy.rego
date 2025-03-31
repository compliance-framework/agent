package compliance_framework.no_controls

import future.keywords.in

violation[{
    "title": "Violation 1",
    "description": "You have been violated.",
    "remarks": "Migrate to not being violated",
}] if {
	"yes" in input.violated
}
