package test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
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

func TestComponent(t *testing.T) {
	awsRegion := "us-east-2"

	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			defer atm.GetAndDestroy("tfstate-bucket/basic", "default-test", map[string]interface{}{})
			component := atm.GetAndDeploy("tfstate-bucket/basic", "default-test", map[string]interface{}{})
			assert.NotNil(t, component)

			bucketID := atm.Output(component, "tfstate_backend_s3_bucket_id")
			assert.NotEmpty(t, bucketID)

			bucketDomainName := atm.Output(component, "tfstate_backend_s3_bucket_domain_name")
			assert.Equal(t, fmt.Sprintf("%s.s3.amazonaws.com", bucketID), bucketDomainName)

			bucketARN := atm.Output(component, "tfstate_backend_s3_bucket_arn")
			assert.Equal(t, fmt.Sprintf("arn:aws:s3:::%s", bucketID), bucketARN)

			dynamodbTableName := atm.Output(component, "tfstate_backend_dynamodb_table_name")
			assert.Equal(t, fmt.Sprintf("%s-lock", bucketID), dynamodbTableName)

			dynamodbTableID := atm.Output(component, "tfstate_backend_dynamodb_table_id")
			assert.Equal(t, fmt.Sprintf("%s-lock", bucketID), dynamodbTableID)

			dynamodbTableARN := atm.Output(component, "tfstate_backend_dynamodb_table_arn")
			assert.True(t, strings.HasSuffix(dynamodbTableARN, dynamodbTableID))

			accessRoleARNs := atm.OutputMapOfObjects(component, "tfstate_backend_access_role_arns")
			assert.NotEmpty(t, accessRoleARNs)

			// Verify that our Bucket has versioning enabled
			actualStatus := aws.GetS3BucketVersioning(t, awsRegion, bucketID)
			expectedStatus := "Enabled"
			assert.Equal(t, expectedStatus, actualStatus)

			policyString := aws.GetS3BucketPolicy(t, awsRegion, bucketID)

			var policy BucketPolicy
			json.Unmarshal([]byte(policyString), &policy)

			statement := policy.Statement[0]

			assert.Equal(t, "DenyIncorrectEncryptionHeader", statement.Sid)
			assert.Equal(t, "s3:PutObject", statement.Action)
			assert.Equal(t, "Deny", statement.Effect)
			assert.Equal(t, fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(t, "AES256", statement.Condition.StringNotEquals["s3:x-amz-server-side-encryption"][0])

			statement = policy.Statement[1]

			assert.Equal(t, "DenyUnEncryptedObjectUploads", statement.Sid)
			assert.Equal(t, "s3:PutObject", statement.Action)
			assert.Equal(t, "Deny", statement.Effect)
			assert.Equal(t, fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(t, "true", statement.Condition.Null["s3:x-amz-server-side-encryption"])

			statement = policy.Statement[2] // Access the new statement

			assert.Equal(t, "EnforceTlsRequestsOnly", statement.Sid)
			assert.Equal(t, "s3:*", statement.Action)
			assert.Equal(t, "Deny", statement.Effect)
			assert.ElementsMatch(t, []string{
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketID),
				fmt.Sprintf("arn:aws:s3:::%s", bucketID),
			}, statement.Resource) // Check for multiple resources
			assert.Equal(t, false, statement.Condition.Bool["aws:SecureTransport"]) // Check the Bool condition

			// Look up the DynamoDB table by name
			table := aws.GetDynamoDBTable(t, awsRegion, dynamodbTableID)

			assert.Equal(t, "ACTIVE", string(table.TableStatus))
			assert.Equal(t, "LockID", *table.KeySchema[0].AttributeName)
			assert.EqualValues(t, "HASH", table.KeySchema[0].KeyType)

			// Verify server-side encryption configuration
			assert.NotEmpty(t, *table.SSEDescription.KMSMasterKeyArn)
			assert.Equal(t, "ENABLED", string(table.SSEDescription.Status))
			assert.Equal(t, "KMS", string(table.SSEDescription.SSEType))

			// Verify TTL configuration
			ttl := aws.GetDynamoDBTableTimeToLive(t, awsRegion, dynamodbTableID)
			assert.Nil(t, ttl.AttributeName)
			assert.Equal(t, "DISABLED", string(ttl.TimeToLiveStatus))

			keys := make([]string, 0, len(accessRoleARNs))
			for k := range accessRoleARNs {
				keys = append(keys, k)
			}
			iamRoleName := keys[0]

			client := aws.NewIamClient(t, awsRegion)
			describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
				RoleName: &iamRoleName,
			})
			assert.NoError(t, err)

			awsRole := describeRoleOutput.Role
			assert.Equal(t, iamRoleName, *awsRole.RoleName)
			assert.Equal(t, fmt.Sprintf("Access role for %s", bucketID), *awsRole.Description)

			assert.EqualValues(t, 3600, *awsRole.MaxSessionDuration)
			assert.Equal(t, "/", *awsRole.Path)
		})
	})
}
