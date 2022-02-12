package module

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// GetAllPolicies returns all policies belonging to a user. These policies are applied
// directly to the user or through means of a group to which a user belongs
func GetAllPolicies(client *iam.Client, user string) (*[]types.AttachedPolicy, error) {
	var policies []types.AttachedPolicy
	// Get user policies
	userPolicies, err := getAttachedUserPolicies(client, user)
	if err != nil {
		return nil, err
	}
	policies = append(policies, *userPolicies...)

	// Get all groups a user belongs to
	groups, err := getUsersGroups(client, user)
	if err != nil {
		return &policies, err
	}

	// Get all group policies affecting a user
	for _, v := range *groups {
		groupPolicies, err := getAttachedGroupPolicies(client, v.GroupName)
		if err == nil {
			policies = append(policies, *groupPolicies...)
		}
	}

	return &policies, nil
}

// getAllArns returns an arn for a given user and all group arns
// to which the user belongs
func getAllArns(client *iam.Client, m Mod) ([]string, error) {
	arns, err := GetGroupArns(client, m.User)
	if err != nil {
		return nil, err
	}
	userArn, err := GetUserArn(*m.Config, m.User)
	if err != nil {
		return nil, err
	}
	arns = append(arns, userArn)
	return arns, nil
}

// EnumUser enumerates an aws user and returns their attached policies,
// as well as the account's arn and the arns of groups the user belongs to
// in the form of a UserEnum object
func EnumUser(mod *Mod, manager *DbManager) (*UserEnum, error) {
	if manager.IsUserAdded(mod.User) {
		return manager.GetUserEnum(mod.User)
	}

	// There is no UserEnum mapped to the user in manager.UsersGathered
	// Populate it on our own by getting all policies and all arns belonging to a user
	client := iam.NewFromConfig(*mod.Config)
	policies, err := GetAllPolicies(client, mod.User)
	if err != nil {
		return nil, err
	}

	inlinePols, err := getInlinePolicies(client, mod.User)
	if err != nil {
		return nil, err
	}

	ue := &UserEnum{AttachedPolicies: policies, InlinePolicies: inlinePols}
	manager.UpdateUser(mod.User, ue)
	return ue, nil
}

// getAttachedUserPolicies returns all policies attached to a user
func getAttachedUserPolicies(client *iam.Client, user string) (*[]types.AttachedPolicy, error) {
	policies, err := client.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{UserName: aws.String(user)})
	if err != nil {
		return nil, err
	}
	return &policies.AttachedPolicies, nil
}

// getInlinePolicies returns all inline user policies
func getInlinePolicies(client *iam.Client, user string) ([]*InlinePolicy, error) {
	userPols, err := client.ListUserPolicies(context.TODO(), &iam.ListUserPoliciesInput{UserName: aws.String(user)})
	if err != nil {
		return nil, err
	}

	policies := make([]*InlinePolicy, 0)
	for _, n := range userPols.PolicyNames {
		pol, err := client.GetUserPolicy(context.TODO(), &iam.GetUserPolicyInput{
			PolicyName: aws.String(n),
			UserName:   aws.String(user),
		})
		if err != nil {
			continue
		}
		decoded, err := url.QueryUnescape(*pol.PolicyDocument)
		if err != nil {
			return nil, err
		}
		var p *Policy
		err = json.Unmarshal([]byte(decoded), &p)
		if err != nil {
			return nil, err
		}
		policies = append(policies, &InlinePolicy{Policy: p, Name: n})
	}
	return policies, nil
}

// getAttachedGroupPolicies returns all policies attached to a group
func getAttachedGroupPolicies(client *iam.Client, group *string) (*[]types.AttachedPolicy, error) {
	policies, err := client.ListAttachedGroupPolicies(context.TODO(), &iam.ListAttachedGroupPoliciesInput{GroupName: group})
	if err != nil {
		return nil, err
	}
	return &policies.AttachedPolicies, nil
}

// getUsersGroups returns all groups to which a user belongs
func getUsersGroups(client *iam.Client, user string) (*[]types.Group, error) {
	groups, err := client.ListGroupsForUser(context.TODO(), &iam.ListGroupsForUserInput{UserName: aws.String(user)})
	if err != nil {
		return nil, err
	}
	return &groups.Groups, nil
}

// GetGroupArns returns a list of arns of groups for which a user belongs
func GetGroupArns(client *iam.Client, user string) ([]string, error) {
	var arns []string
	groups, err := getUsersGroups(client, user)
	if err != nil {
		return nil, err
	}
	for _, v := range *groups {
		arns = append(arns, *v.Arn)
	}
	return arns, nil
}

// EnumLambdaFuncs returns all lambda functions (and all their versions) belonging to an account
func EnumLambdaFuncs(client *lambda.Client) ([]*lambda.ListFunctionsOutput, error) {
	funcsOutput := make([]*lambda.ListFunctionsOutput, 0)
	input := &lambda.ListFunctionsInput{}
	funcPag := lambda.NewListFunctionsPaginator(client, input)

	for funcPag.HasMorePages() {
		if output, err := funcPag.NextPage(context.TODO()); err != nil {
			return nil, err
		} else {
			funcsOutput = append(funcsOutput, output)
		}
	}

	return funcsOutput, nil
}

// GetLambdaConfig returns a lambda config
func GetLambdaClient(conf aws.Config) *lambda.Client {
	return lambda.NewFromConfig(conf)
}

// GetUserArn returns the ARN for a user
func GetUserArn(conf aws.Config, user string) (string, error) {
	client := sts.NewFromConfig(conf)
	identity, err := client.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(identity.Arn), nil
}
