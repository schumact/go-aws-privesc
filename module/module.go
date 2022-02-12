package module

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/schumact/pacu-go/database"
)

const (
	createLoginProfile      = "iam:CreateLoginProfile"
	updateLoginProfile      = "iam:UpdateLoginProfile"
	createAccessKey         = "iam:CreateAccessKey"
	createPolicyVersion     = "iam:CreatePolicyVersion"
	setDefaultPolicyVersion = "iam:SetDefaultPolicyVersion"
	passRole                = "iam:PassRole"
	attachUserPolicy        = "iam:AttachUserPolicy"
	attachGroupPolicy       = "iam:AttachGroupPolicy"
	attachRolePolicy        = "iam:AttachRolePolicy"
	addUserToGroup          = "iam:AddUserToGroup"
	putUserPolicy           = "iam:PutUserPolicy"
	putGroupPolicy          = "iam:PutGroupPolicy"
	updateFunctionCode      = "lambda:UpdateFunctionCode"
	databaseName            = "pacu-go"
)

var modules = map[string]helpInfo{
	createLoginProfile: {desc: "Users with iam:CreateLoginProfile on other users can set a console login password for users without one set.\n " +
		"This command contains an optional argument for the new password of the user. (Default: Pa$$w0rd123!)"},
	updateLoginProfile: {desc: "Users with iam:UpdateLoginProfile on other users can change the console login password for those users.\n " +
		"This command contains an optional argument for the new password of the user. (Default: Pa$$w0rd123!)"},
	createAccessKey: {desc: "Users with iam:CreateAccessKey permission can create access keys for user(s) specified in the policy."},
	createPolicyVersion: {desc: "Users with  iam:CreatePolicyVersion permission are allowed to create a new version of an existing policy. " +
		"Consequently, they can create a policy that allows more permissions than what they currently have."},
	setDefaultPolicyVersion: {desc: "When modifying a policy, AWS automatically creates a new policy version with the changes. Those " +
		"changes can be undone by reverting the policy to a previous version. Users with iam:SetDefaultPolicyVersion can " +
		"set which version of the policy is the default (active) version."},
	passRole: {desc: "The iam:PassRole permission allows a user to pass a role to another AWS resource.\n " +
		"The ec2:RunInstances permission allows a user to run EC2 instances. With these two permissions, the user can create a " +
		"new EC2 instance which they have SSH access to, pass a role to the instance with permissions that the user does not have currently, " +
		"log into the instance, and request AWS keys for the role."},
	attachUserPolicy: {desc: "Users with the iam:AttachUserPolicy can attach managed policies to user accounts, potentially allowing them " +
		"to attach policies with permissions that they don't currently have to their own account.\n This command requires the name of a user " +
		"to be passed as an argument."},
	attachGroupPolicy: {desc: "Users with iam:AttachGroupPolicy can attach managed policies to groups, potentially allowing them to attach " +
		"policies with permissions that they don't currently have to a group that they are part of.\n This command requires the name of a group " +
		"to be passed as an argument."},
	attachRolePolicy: {desc: "Users with iam:AttachRolePolicy can attach managed policies to roles, potentially allowing them to attach policies " +
		"with permissions that they don't currently have to a role that they can assume.\n This command requires the name of a role " +
		"to be passed as an argument"},
	addUserToGroup: {desc: "Users with iam:AddUserToGroup permission can add users to new groups, potentially allowing them to add their own user " +
		"account to a group that has more privileges than what the user currently has.\n This command requires the name of a group " +
		"to be passed as an argument"},
	putUserPolicy: {desc: "Users with iam:PutUserPolicy can create or update an inline policy for a user, potentially allowing them to add " +
		"permissions that they don't currently have to their account.\n This command requires the name of a user to be passed as an argument."},
	putGroupPolicy: {desc: "Users with the iam:PutGroupPolicy can create or update an inline policy for a group, potentially allowing them to add " +
		"permissions that they don't currently have to their account.\n This command requires the name of a group to be passed as an argument"},
	updateFunctionCode: {desc: "Users with the lambda:UpdateFunctionCode permission can modify the code of an existing Lambda function so that it " +
		"escalates their privileges when invoked.\n This command requires 2 arguments. The first argument should be the function name " +
		"to abuse and the second argument is a path to a zip file containing the code to be used during the UpdateFunctionCode call"},
}

type (
	// Contains module info for displaying to
	helpInfo struct {
		desc string
	}

	// Module is the interface that runs an aws command
	Module interface {
		Run(bool, *DbManager, ...string) (string, error)
	}

	DbManager struct {
		Database     *database.Sqlite
		UserGathered map[string]*UserEnum // map[aws_user]bool. True if policies for a user were already queried
	}

	// UserEnum contains info about an AWS user
	UserEnum struct {
		AttachedPolicies *[]types.AttachedPolicy // policies attached to a user
		InlinePolicies   []*InlinePolicy
		// Arns             []string //arns of the user the groups to which the user belongs
		LambdaFunctions []*funcData
	}

	// Mod contains all the relevant info needed for an aws command to run
	Mod struct {
		Config *aws.Config // profile for running the command
		User   string
	}

	Policy struct {
		Name      string
		Version   string `json:"Version"`
		Statement []struct {
			Effect    string      `json:"Effect"`
			Action    interface{} `json:"Action"`
			NotAction interface{} `json:"NotAction"`
			Resource  string      `json:"Resource"`
		} `json:"Statement"`
	}

	InlinePolicy struct {
		Policy *Policy
		Name   string
	}
)

// UpdateUser updates DbManager.UserGathered map. If a single module IAM module was
// called, a user's attached group and user policies would have already been queried.
// If that is the case, UserGathered should be populated
func (dm *DbManager) UpdateUser(user string, ue *UserEnum) {
	dm.UserGathered[user] = ue
}

// ResetUser updates DbManager.UserGathered map by setting the UserEnum value associated with a
// user to an empty UserEnum
func (dm *DbManager) ResetUser(user string) error {
	if _, ok := dm.UserGathered[user]; ok {
		dm.UserGathered[user] = nil
		return nil
	}
	return fmt.Errorf("no info gathered for %s", user)
}

// IsUserAdded returns a bool indicating whether or not a UserEnum object
// in DbManager.UserGathered has been populated for a user
func (dm *DbManager) IsUserAdded(user string) bool {
	if val, ok := dm.UserGathered[user]; !ok {
		return false
	} else if val != nil {
		return true
	}
	return false
}

// GetUserEnum returns the UserEnum object associated with a user
func (dm *DbManager) GetUserEnum(user string) (*UserEnum, error) {
	if val, ok := dm.UserGathered[user]; ok && val != nil {
		return val, nil
	}
	return nil, fmt.Errorf("couldn't find UserEnum for %s", user)
}

// AddLambdaFuncs associates all lambda functions ($LATEST version) with a user
func (dm *DbManager) AddLambdaFuncs(user string, funcs []*funcData) error {
	val, ok := dm.UserGathered[user]
	if !ok {
		return fmt.Errorf("a user with the username %s has not been enumerated", user)
	}
	val.LambdaFunctions = funcs
	// TODO change this once I implement a DB
	return dm.exportFunctions(funcs)
}

// exportFunctions helps write lambda functions to the database (currently a text file)
func (dm *DbManager) exportFunctions(funcs []*funcData) error {
	for _, v := range funcs {
		polNames := ""
		polLen := len(v.policies)
		for i, p := range v.policies {
			if i == polLen-1 {
				polNames += p.Name
			} else {
				polNames += fmt.Sprintf("%s,", p.Name)
			}
		}
		// ehh. Just ignore the error while I don't have a db
		dm.Database.WriteText(fmt.Sprintf("Lambda function - Arn: %s, Role:%s, Handler:%s, Policies: %s\n", v.Arn, v.Role, v.Handler, polNames))
	}
	return nil
}

// GetLambdaFuncs associates all lambda functions ($LATEST version) with a user
func (dm *DbManager) GetLambdaFuncs(user string) ([]*funcData, error) {
	val, ok := dm.UserGathered[user]
	if !ok {
		return nil, fmt.Errorf("a user with the username %s has not been enumerated", user)
	}
	return val.LambdaFunctions, nil
}

// NewDbManager returns a new instance of a DbManager object
func NewDbManager() (*DbManager, error) {
	manager := &DbManager{}
	manager.Database = database.CreateDb()
	if err := manager.Database.SetFile(); err != nil {
		fmt.Printf("[-] Error setting output file. This should be removed at some point. %v\n", err)
	}
	manager.UserGathered = make(map[string]*UserEnum)
	return manager, manager.Database.OpenConn(databaseName)
}

// ListModules prints info for all available modules
func ListModules() {
	for k, v := range modules {
		fmt.Printf("Module: %s. Info: %s \n\n", k, v.desc)
	}
}

// getModuleHelp return a description of a privesc module
func GetModuleHelp(name string) (string, error) {
	if v, ok := modules[name]; ok {
		return fmt.Sprintf("Module: %s. Info: %s \n\n", name, v.desc), nil
	}
	return "", fmt.Errorf("a module named %s wasn't found. Make sure your casing is right", name)
}

// ModuleFactory returns a newly initialized Module for a module with the passed in name
func ModuleFactory(name string, conf *aws.Config, user string) (Module, error) {
	switch name {
	case createLoginProfile:
		return &IAMCreateLoginProfile{Mod: Mod{Config: conf, User: user}}, nil
	case updateLoginProfile:
		return &IAMUpdateLoginProfile{Mod: Mod{Config: conf, User: user}}, nil
	case createAccessKey:
		return &IAMCreateAccessKey{Mod: Mod{Config: conf, User: user}}, nil
	case createPolicyVersion:
		return &IAMCreatePolicyVersion{Mod: Mod{Config: conf, User: user}}, nil
	case setDefaultPolicyVersion:
		return &IAMSetDefaultPolicyVersion{Mod: Mod{Config: conf, User: user}}, nil
	case passRole:
		return &IAMPassRole{Mod: Mod{Config: conf, User: user}}, nil
	case attachUserPolicy:
		return &IAMAttachUserPolicy{Mod: Mod{Config: conf, User: user}}, nil
	case attachGroupPolicy:
		return &IAMAttachGroupPolicy{Mod: Mod{Config: conf, User: user}}, nil
	case addUserToGroup:
		return &IAMAddUserToGroup{Mod: Mod{Config: conf, User: user}}, nil
	case putUserPolicy:
		return &IAMPutUserPolicy{Mod: Mod{Config: conf, User: user}}, nil
	case attachRolePolicy:
		return &IAMAttachRolePolicy{Mod: Mod{Config: conf, User: user}}, nil
	case putGroupPolicy:
		return &IAMPutGroupPolicy{Mod: Mod{Config: conf, User: user}}, nil
	case updateFunctionCode:
		return &LambdaUpdateFunctionCode{Mod: Mod{Config: conf, User: user}}, nil
	default:
		return nil, fmt.Errorf("module '%s' could not be found", name)
	}
}

// GetDefaultConfig returns the default AWS configuration
func GetDefaultConfig() (aws.Config, error) {
	return config.LoadDefaultConfig(context.TODO())
}

// GetStaticConfig return an aws config
func GetStaticConfig(accessKey string, secretKey string) (aws.Config, error) {
	return config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(
		credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretKey,
			},
		}))
}
