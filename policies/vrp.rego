package agentgate.vrp

import rego.v1

# ---------------------------------------------------------------------------
# Huawei VRP risk tiering.
#
# Stage-3 surface: the normalizer is real, the executor talks to a simulator
# unless a device credential is configured. The rules below are written as if
# against a live device so that swapping the adapter in is the only change
# needed to go live.
# ---------------------------------------------------------------------------

# Configuration that can sever the management plane.
deny contains "vrp: reset saved-configuration erases the device configuration" if {
	input.action.args.resets_saved_config == true
}

deny contains reason if {
	input.action.args.touches_local_users == true
	reason := "vrp: local-user changes rewrite device credentials"
}

deny contains reason if {
	input.action.args.acl_deny_all == true
	reason := "vrp: ACL rule denies a wildcard source/destination pair and can cut off management access"
}

deny contains reason if {
	input.action.args.block_count > 6
	reason := sprintf("vrp: %d configuration blocks in one change is a config rewrite, not a change",
		[input.action.args.block_count])
}

deny contains reason if {
	input.action.args.shutdown_count > 0
	input.action.blast_radius.production == true
	reason := "vrp: shutting an interface down on a production device is a service outage"
}

approval contains reason if {
	input.action.args.shutdown_count > 0
	reason := "vrp: shutting an interface down interrupts traffic"
}

approval contains reason if {
	input.action.args.has_undo == true
	reason := "vrp: undo directives remove existing configuration"
}

approval contains reason if {
	input.action.args.route_policy_count > 0
	reason := "vrp: route-policy changes redirect traffic and need a NetGuard impact preview"
}

approval contains reason if {
	input.action.args.bgp_peer_count > 0
	reason := "vrp: BGP peer changes affect reachability beyond this device"
}

approval contains reason if {
	input.action.verb == "config"
	reason := "vrp: every device configuration change needs a human in the loop"
}

flags contains reason if {
	input.action.args.multi_block == true
	reason := "vrp: change spans multiple configuration blocks"
}

flags contains reason if {
	input.action.args.line_count > 40
	reason := sprintf("vrp: %d configuration lines in a single call", [input.action.args.line_count])
}

# ---------------------------------------------------------------------------
# Allow reasons
# ---------------------------------------------------------------------------

allow contains reason if {
	input.action.verb == "read"
	reason := sprintf("vrp: reading configuration from %s does not change the device", [input.action.resource.name])
}

allow contains reason if {
	input.action.verb == "config"
	input.action.args.block_count <= 1
	input.action.args.shutdown_count == 0
	input.action.args.bgp_peer_count == 0
	reason := "vrp: a single non-disruptive configuration block, with a NetGuard reachability preview before it runs"
}
