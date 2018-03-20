package main

import(
	"github.com/casbin/casbin"
)
const(
	userPrefix = "usr_"
	typePrefix = "type_"
)

var enf *casbin.Enforcer

// This file illustrate a method where we use casbin to manage:
// (1) A DAG of user, role, privilege group, privilege
// (2) A DAG of resources (objects, types)
func main() {
	enf = casbin.NewEnforcer("rbac.conf", "rbac.csv")
	user1 := "di"
	user2 := "kancheng"
	org1 := "org1"
	org2 := "org2"
	// user di (org1, admin) has the backup permission for vm1_1
	hasPermissionForObject(user1, org1, "vm1_1", "backup") // true
	// user kancheng (org2, end_user) has view permission for hyperv1_1
	hasPermissionForObject(user2, org2, "hyperv1_1", "view") // true

	// user di has backup permission for at least one object in type vm
	typeName := "vm"
	hasPermissionForAtLeastOneObjInType(user1, org1, typeName, "backup") // true
}

// check if a (user, org) pair has permission to (objectId, operation) pair
func hasPermissionForObject(
	user string,
	org string,
	objectId string,
	operation string,
	) bool {
	user = constructUserName(user, org)
	return enf.Enforce(user, objectId, operation, org)
}

func hasPermissionForAtLeastOneObjInType(
	user string,
	org string,
	typeName string,
	operation string,
) bool {
	user = constructUserName(user, org)
	typeName = typePrefix + typeName
	return enf.Enforce(user, typeName, operation, org)
}


func constructUserName(user string, org string) string {
	return userPrefix + org + "_" + user
}