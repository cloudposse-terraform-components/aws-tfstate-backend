package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
)

type LifecyclePolicyRuleSelection struct {
	TagStatus     string   `json:"tagStatus"`
	TagPrefixList []string `json:"tagPrefixList"`
	CountType     string   `json:"countType"`
	CountNumber   int      `json:"countNumber"`
}
type LifecyclePolicyRule struct {
	RulePriority int                          `json:"rulePriority"`
	Description  string                       `json:"description"`
	Selection    LifecyclePolicyRuleSelection `json:"selection"`
	Action       map[string]string            `json:"action"`
}
type LifecyclePolicy struct {
	Rules []LifecyclePolicyRule `json:"rules"`
}

type BucketPolicy struct {
	Version   string `json:"Version"`
	Statement []struct {
		Sid       string      `json:"Sid,omitempty"`
		Principal string      `json:"Principal"`
		Effect    string      `json:"Effect"`
		Action    string      `json:"Action"`
		Resource  interface{} `json:"Resource"` // Changed to interface{} to accommodate array
		Condition struct {
			StringEquals    map[string]string   `json:"StringEquals,omitempty"`
			StringNotEquals map[string][]string `json:"StringNotEquals,omitempty"`
			Null            map[string]string   `json:"Null,omitempty"`
			Bool            map[string]bool     `json:"Bool,omitempty"` // Added Bool for new condition
			ArnLike         map[string][]string `json:"ArnLike,omitempty"`
		} `json:"Condition"`
	} `json:"Statement"`
}

type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestBasic() {
	const component = "tfstate-bucket/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	bucketDomainName := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_domain_name")
	assert.Equal(s.T(), fmt.Sprintf("%s.s3.amazonaws.com", bucketID), bucketDomainName)

	bucketARN := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_arn")
	assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s", bucketID), bucketARN)

	dynamodbTableName := atmos.Output(s.T(), options, "tfstate_backend_dynamodb_table_name")
	assert.Equal(s.T(), fmt.Sprintf("%s-lock", bucketID), dynamodbTableName)

	dynamodbTableID := atmos.Output(s.T(), options, "tfstate_backend_dynamodb_table_id")
	assert.Equal(s.T(), fmt.Sprintf("%s-lock", bucketID), dynamodbTableID)

	dynamodbTableARN := atmos.Output(s.T(), options, "tfstate_backend_dynamodb_table_arn")
	assert.True(s.T(), strings.HasSuffix(dynamodbTableARN, dynamodbTableID))

	accessRoleARNs := atmos.OutputMapOfObjects(s.T(), options, "tfstate_backend_access_role_arns")
	assert.NotEmpty(s.T(), accessRoleARNs)

	// Verify that our Bucket has versioning enabled
	actualStatus := aws.GetS3BucketVersioning(s.T(), awsRegion, bucketID)
	expectedStatus := "Enabled"
	assert.Equal(s.T(), expectedStatus, actualStatus)

	policyString := aws.GetS3BucketPolicy(s.T(), awsRegion, bucketID)

	var policy BucketPolicy
	json.Unmarshal([]byte(policyString), &policy)

	for _, statement := range policy.Statement {
		switch statement.Sid {
		case "DenyIncorrectEncryptionHeader":
			assert.Equal(s.T(), "s3:PutObject", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(s.T(), "AES256", statement.Condition.StringNotEquals["s3:x-amz-server-side-encryption"][0])
		case "DenyUnEncryptedObjectUploads":
			assert.Equal(s.T(), "s3:PutObject", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(s.T(), "true", statement.Condition.Null["s3:x-amz-server-side-encryption"])
		case "EnforceTlsRequestsOnly":
			assert.Equal(s.T(), "s3:*", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.ElementsMatch(s.T(), []string{
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketID),
				fmt.Sprintf("arn:aws:s3:::%s", bucketID),
			}, statement.Resource) // Check for multiple resources
			assert.Equal(s.T(), false, statement.Condition.Bool["aws:SecureTransport"]) // Check the Bool condition
		}
	}

	// Look up the DynamoDB table by name
	table := aws.GetDynamoDBTable(s.T(), awsRegion, dynamodbTableID)

	assert.Equal(s.T(), "ACTIVE", string(table.TableStatus))
	assert.Equal(s.T(), "LockID", *table.KeySchema[0].AttributeName)
	assert.EqualValues(s.T(), "HASH", table.KeySchema[0].KeyType)

	// Verify server-side encryption configuration
	assert.NotEmpty(s.T(), *table.SSEDescription.KMSMasterKeyArn)
	assert.Equal(s.T(), "ENABLED", string(table.SSEDescription.Status))
	assert.Equal(s.T(), "KMS", string(table.SSEDescription.SSEType))

	// Verify TTL configuration
	ttl := aws.GetDynamoDBTableTimeToLive(s.T(), awsRegion, dynamodbTableID)
	assert.Nil(s.T(), ttl.AttributeName)
	assert.Equal(s.T(), "DISABLED", string(ttl.TimeToLiveStatus))

	keys := make([]string, 0, len(accessRoleARNs))
	for k := range accessRoleARNs {
		keys = append(keys, k)
	}
	iamRoleName := keys[0]

	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &iamRoleName,
	})
	assert.NoError(s.T(), err)

	awsRole := describeRoleOutput.Role
	assert.Equal(s.T(), iamRoleName, *awsRole.RoleName)
	assert.Equal(s.T(), fmt.Sprintf("Access role for %s", bucketID), *awsRole.Description)

	assert.EqualValues(s.T(), 3600, *awsRole.MaxSessionDuration)
	assert.Equal(s.T(), "/", *awsRole.Path)

	s.DriftTest(component, stack, nil)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "tfstate-bucket/disabled"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	s.VerifyEnabledFlag(component, stack, nil)
}

func (s *ComponentSuite) TestStateLock() {
	const component = "tfstate-bucket/statelock"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	bucketDomainName := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_domain_name")
	assert.Equal(s.T(), fmt.Sprintf("%s.s3.amazonaws.com", bucketID), bucketDomainName)

	bucketARN := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_arn")
	assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s", bucketID), bucketARN)

	// Verify that DynamoDB table outputs are empty since dynamodb_enabled: false
	dynamodbTableName := atmos.Output(s.T(), options, "tfstate_backend_dynamodb_table_name")
	assert.Empty(s.T(), dynamodbTableName)

	dynamodbTableID := atmos.Output(s.T(), options, "tfstate_backend_dynamodb_table_id")
	assert.Empty(s.T(), dynamodbTableID)

	dynamodbTableARN := atmos.Output(s.T(), options, "tfstate_backend_dynamodb_table_arn")
	assert.Empty(s.T(), dynamodbTableARN)

	accessRoleARNs := atmos.OutputMapOfObjects(s.T(), options, "tfstate_backend_access_role_arns")
	assert.NotEmpty(s.T(), accessRoleARNs)

	// Verify that our Bucket has versioning enabled
	actualStatus := aws.GetS3BucketVersioning(s.T(), awsRegion, bucketID)
	expectedStatus := "Enabled"
	assert.Equal(s.T(), expectedStatus, actualStatus)

	policyString := aws.GetS3BucketPolicy(s.T(), awsRegion, bucketID)

	var policy BucketPolicy
	json.Unmarshal([]byte(policyString), &policy)

	for _, statement := range policy.Statement {
		switch statement.Sid {
		case "DenyIncorrectEncryptionHeader":
			assert.Equal(s.T(), "s3:PutObject", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(s.T(), "AES256", statement.Condition.StringNotEquals["s3:x-amz-server-side-encryption"][0])
		case "DenyUnEncryptedObjectUploads":
			assert.Equal(s.T(), "s3:PutObject", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(s.T(), "true", statement.Condition.Null["s3:x-amz-server-side-encryption"])
		case "EnforceTlsRequestsOnly":
			assert.Equal(s.T(), "s3:*", statement.Action)
			assert.Equal(s.T(), "Deny", statement.Effect)
			assert.ElementsMatch(s.T(), []string{
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketID),
				fmt.Sprintf("arn:aws:s3:::%s", bucketID),
			}, statement.Resource) // Check for multiple resources
			assert.Equal(s.T(), false, statement.Condition.Bool["aws:SecureTransport"]) // Check the Bool condition
		}
	}

	// Verify IAM roles are created correctly
	keys := make([]string, 0, len(accessRoleARNs))
	for k := range accessRoleARNs {
		keys = append(keys, k)
	}
	iamRoleName := keys[0]

	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &iamRoleName,
	})
	assert.NoError(s.T(), err)

	awsRole := describeRoleOutput.Role
	assert.Equal(s.T(), iamRoleName, *awsRole.RoleName)
	assert.Equal(s.T(), fmt.Sprintf("Access role for %s", bucketID), *awsRole.Description)

	assert.EqualValues(s.T(), 3600, *awsRole.MaxSessionDuration)
	assert.Equal(s.T(), "/", *awsRole.Path)

	s.DriftTest(component, stack, nil)
}

// AssumeRolePolicy represents the structure of an IAM assume role policy document
type AssumeRolePolicy struct {
	Version   string `json:"Version"`
	Statement []struct {
		Sid       string      `json:"Sid,omitempty"`
		Effect    string      `json:"Effect"`
		Principal interface{} `json:"Principal"`
		Action    interface{} `json:"Action"`
		Condition struct {
			StringEquals map[string]interface{} `json:"StringEquals,omitempty"`
			ArnLike      map[string]interface{} `json:"ArnLike,omitempty"`
		} `json:"Condition,omitempty"`
	} `json:"Statement"`
}

// TestWithOrgID tests that use_organization_id=true uses the aws:PrincipalOrgID condition
func (s *ComponentSuite) TestWithOrgID() {
	const component = "tfstate-bucket/with-org-id"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	accessRoleARNs := atmos.OutputMapOfObjects(s.T(), options, "tfstate_backend_access_role_arns")
	assert.NotEmpty(s.T(), accessRoleARNs)

	// Get the first role name
	keys := make([]string, 0, len(accessRoleARNs))
	for k := range accessRoleARNs {
		keys = append(keys, k)
	}
	iamRoleName := keys[0]

	// Get the role and its assume role policy
	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &iamRoleName,
	})
	assert.NoError(s.T(), err)

	// Parse the assume role policy (AWS returns it URL-encoded)
	decodedPolicy, err := url.QueryUnescape(*describeRoleOutput.Role.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	var assumeRolePolicy AssumeRolePolicy
	err = json.Unmarshal([]byte(decodedPolicy), &assumeRolePolicy)
	assert.NoError(s.T(), err)

	// Verify that at least one statement has aws:PrincipalOrgID condition
	hasOrgIDCondition := false
	hasPrincipalWildcard := false
	for _, statement := range assumeRolePolicy.Statement {
		if statement.Effect == "Allow" {
			// Check for aws:PrincipalOrgID condition
			if orgID, ok := statement.Condition.StringEquals["aws:PrincipalOrgID"]; ok && orgID != nil {
				hasOrgIDCondition = true
			}
			// Check if principal is "*" (wildcard)
			if principal, ok := statement.Principal.(string); ok && principal == "*" {
				hasPrincipalWildcard = true
			}
			if principalMap, ok := statement.Principal.(map[string]interface{}); ok {
				if aws, ok := principalMap["AWS"]; ok {
					if awsStr, ok := aws.(string); ok && awsStr == "*" {
						hasPrincipalWildcard = true
					}
				}
			}
		}
	}

	assert.True(s.T(), hasOrgIDCondition, "Expected trust policy to have aws:PrincipalOrgID condition when use_organization_id=true")
	assert.True(s.T(), hasPrincipalWildcard, "Expected trust policy to have wildcard principal when use_organization_id=true")

	s.DriftTest(component, stack, nil)
}

// TestWithoutOrgID tests that use_organization_id=false lists individual account roots
func (s *ComponentSuite) TestWithoutOrgID() {
	const component = "tfstate-bucket/without-org-id"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "tfstate_backend_s3_bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	accessRoleARNs := atmos.OutputMapOfObjects(s.T(), options, "tfstate_backend_access_role_arns")
	assert.NotEmpty(s.T(), accessRoleARNs)

	// Get the first role name
	keys := make([]string, 0, len(accessRoleARNs))
	for k := range accessRoleARNs {
		keys = append(keys, k)
	}
	iamRoleName := keys[0]

	// Get the role and its assume role policy
	client := aws.NewIamClient(s.T(), awsRegion)
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &iamRoleName,
	})
	assert.NoError(s.T(), err)

	// Parse the assume role policy (AWS returns it URL-encoded)
	decodedPolicy, err := url.QueryUnescape(*describeRoleOutput.Role.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	var assumeRolePolicy AssumeRolePolicy
	err = json.Unmarshal([]byte(decodedPolicy), &assumeRolePolicy)
	assert.NoError(s.T(), err)

	// Verify that no statement has aws:PrincipalOrgID condition
	// and that principals are account root ARNs (not wildcards)
	hasOrgIDCondition := false
	hasAccountRootPrincipal := false
	for _, statement := range assumeRolePolicy.Statement {
		if statement.Effect == "Allow" {
			// Check that there's no aws:PrincipalOrgID condition
			if orgID, ok := statement.Condition.StringEquals["aws:PrincipalOrgID"]; ok && orgID != nil {
				hasOrgIDCondition = true
			}
			// Check if principal contains account root ARN pattern
			if principalMap, ok := statement.Principal.(map[string]interface{}); ok {
				if aws, ok := principalMap["AWS"]; ok {
					// Could be a string or array
					switch v := aws.(type) {
					case string:
						if strings.Contains(v, ":root") {
							hasAccountRootPrincipal = true
						}
					case []interface{}:
						for _, p := range v {
							if pStr, ok := p.(string); ok && strings.Contains(pStr, ":root") {
								hasAccountRootPrincipal = true
							}
						}
					}
				}
			}
		}
	}

	assert.False(s.T(), hasOrgIDCondition, "Expected trust policy to NOT have aws:PrincipalOrgID condition when use_organization_id=false")
	assert.True(s.T(), hasAccountRootPrincipal, "Expected trust policy to have account root ARN principals when use_organization_id=false")

	s.DriftTest(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
