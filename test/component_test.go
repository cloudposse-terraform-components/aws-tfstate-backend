package test

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
