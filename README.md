# Welcome to the Detection-as-Code (DAC) Workshop
This guide will provide you with a step-by-step of all the commands that will be needed during the hands-on portion of the workshop. If you have questions, feel free to ask your group moderator.

**Helpful Links 
- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)
- [What are Packs?](https://docs.panther.com/writing-detections/detection-packs)
- [Panther Analysis Tool](https://docs.panther.com/panther-developer-workflows/panther-analysis-tool#overview)
- [API Key](https://docs.panther.com/panther-developer-workflows/api#how-to-use-panthers-api)
- [Lookup Tables](https://docs.panther.com/enrichment/lookup-tables)



## Lesson 1 - Writing a Detection for CloudTrail IAM Logs

**Lesson 1 Steps**
1. In the Panther Console - Navigate to Build > Packs > Core AWS Packs
2. Select "Rule" and give it a unique name "Brandon's Failed Login Detection" (Use your own name or initials)
3. Select the log source "AWS.CloudTrail" and set Severity to "Medium"
4. Select Functions and Tests in the tab
5. Create a Unit Test and copy and paste the sample event from Cloudtrail below. We will use this to create our detection. 
6. Import deep_get function from the panther_base_helpers library ```from panther_base_helpers import deep_get```
7. Return the event for a login ```return deep_get(event, "responseElements", "ConsoleLogin") == "Failure"```
8. Final detection should look something like below:

```
from panther_base_helpers import deep_get

def rule(event):
    return deep_get(event, "responseElements", "ConsoleLogin") == "Failure"

```

**CloudTrail Log - Failed Login Attempt**
```
{
	"additionalEventData": {
		"LoginTo": "https://console.aws.amazon.com/console/",
		"MFAUsed": "No",
		"MobileVersion": "No"
	},
	"awsRegion": "us-east-1",
	"eventID": "1",
	"eventName": "ConsoleLogin",
	"eventSource": "signin.amazonaws.com",
	"eventTime": "2019-01-01T00:00:00Z",
	"eventType": "AwsConsoleSignIn",
	"eventVersion": "1.05",
	"p_event_time": "2021-06-04 09:59:53.650807",
	"p_log_type": "AWS.CloudTrail",
	"p_parse_time": "2021-06-04 10:02:33.650807",
	"recipientAccountId": "123456789012",
	"requestParameters": null,
	"responseElements": {
		"ConsoleLogin": "Failure"
	},
	"sourceIPAddress": "111.111.111.111",
	"userAgent": "Mozilla",
	"userIdentity": {
		"accountId": "123456789012",
		"arn": "arn:aws:iam::123456789012:user/tester",
		"principalId": "1111",
		"type": "IAMUser",
		"userName": "tester"
	}
}
```



## Lesson 2 - Tuning an pre-existing detection


**Exercise 2 Steps**
1. In the Panther Console - Navigate to Build > Packs > AWS Core Pack
2. Select the AWS GuardDuty High Severity Finding
3. Duplicate your tab
4. Navigate to Build > Detections > Create New and Create a new rule (Do not clone packed rule)
5. Name the detection a unique name with your initials - Sample "AWS GuardDuty High Severity Finding - Brandon"
6. Copy and Paste the code from the original Packed Rule
7. Grab the severity function below:
```
def severity(event):
    if event.get("field") == "value":
        return "INFO"
    return "HIGH"
```
8. Add the severity function anywhere under the rule function
9. Copy over the test event with the sample log event from AWS GuardDuty Log Below
10. Modify the severity function to return a "Low" event when the user is your own email or otherwise return a "High" event (Hint - you will have to use deep_get for this)
11. Test your changes using the unit test
12. Save Changes


**AWS GuardDuty Sample Log**
```
{
"accountId": "123456789012",
"arn": "arn:aws:guardduty:us-west-2:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/90b82273685661b9318f078d0851fe9a",
"createdAt": "2020-02-14T18:12:22.316Z",
"description": "Principal AssumedRole:IAMRole attempted to add a highly permissive policy to themselves.",
"id": "eeb88ab56556eb7771b266670dddee5a",
"partition": "aws",
"region": "us-east-1",
"schemaVersion": "2.0",
"service": {
	"action": {
		"actionType": "AWS_API_CALL",
		"awsApiCallAction": {
			"affectedResources": {
				"AWS::IAM::Role": "arn:aws:iam::123456789012:role/IAMRole"
			},
			"api": "PutRolePolicy",
			"callerType": "Domain",
			"domainDetails": {
				"domain": "cloudformation.amazonaws.com"
			},
			"serviceName": "iam.amazonaws.com"
		}
	},
	"additionalInfo": {},
	"archived": false,
	"count": 1,
	"detectorId": "111111bbbbbbbbbb5555555551111111",
	"eventFirstSeen": "2020-02-14T17:59:17Z",
	"eventLastSeen": "2020-02-14T17:59:17Z",
	"evidence": null,
	"resourceRole": "TARGET",
	"serviceName": "guardduty"
},
"severity": 8,
"title": "Principal AssumedRole:IAMRole attempted to add a policy to themselves that is highly permissive.",
"type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
"updatedAt": "2020-02-14T18:12:22.316Z"
}
```


## Exercise 3 - Enrich a Detection with GreyNoise
Write a detection while using the GreyNoise helper to apply threat intelligence directly into a detection. For this example, we will use a brute force detection with the sample data from Okta below. 



**Exercise 3 Steps**
1. Create a new detection in the Panther Console Build > Detections > Create New
2. Name the detection with your initials (Demo GreyNoise Detection Brandon)
3. Select the AWS CloudTrail Brute Force Attempt and set a Medium Severity
4. Select Functions & Tests to begin writing the detection
5. Copy and Paste the Event Log below into a new unit test. You'll use this information to write your detection. 
6. Import the deep_get function and the GetGreyNoiseObject function 
```
from panther_greynoise_helpers import GetGreyNoiseObject
from panther_base_helpers import deep_get
```
7. In the rule function, begin by declaring a global variable "noise" and setting it to the GetGreyNoiseObject event pulled in from the helper function
```
global noise 
noise = GetGreyNoiseObject(event)
```
8. Create an if statement that returns true when a user session starts and a failed login is detection (same statement as the one we used in the first exercise.
9. Your rule function should look something like this: 
```
def rule(event):
    global noise 
    noise = GetGreyNoiseObject(event)
    if (event.get("eventType") == "user.session.start" and deep_get(event, "outcome", "result") == "FAILURE"):
        return True
    return False
```
10. Add the severity function to return a "critical" alert when an IP is deemed "malicious" by GreyNoise and to return a "info" level alert when IP is deemed "benign". For all others, return "medium" severity. 
```
def severity(event):
    if noise.classification("client.ipAddress") == "malicious":
        return "CRITICAL"
    if noise.classification("client.ipAddress") == "benign":
        return "INFO"
    return "MEDIUM"

```
11. Test your detection and modify as needed


**Sample AWS.CloudTrail Event Data for Brute Force Detection**
```
{
	"additionalEventData": {
		"LoginTo": "https://console.aws.amazon.com/console/",
		"MFAUsed": "No",
		"MobileVersion": "No"
	},
	"awsRegion": "us-east-1",
	"eventID": "1",
	"eventName": "ConsoleLogin",
	"eventSource": "signin.amazonaws.com",
	"eventTime": "2019-01-01T00:00:00Z",
	"eventType": "AwsConsoleSignIn",
	"eventVersion": "1.05",
	"p_event_time": "2021-06-04 09:59:53.650807",
	"p_log_type": "AWS.CloudTrail",
	"p_parse_time": "2021-06-04 10:02:33.650807",
	"p_enrichment": {
		"greynoise_noise_basic": {
				"client.ipAddress": {
					"actor": "EviLCorp",
					"classification": "benign",
					"ip": "1.2.3.4"
			}
		}	
	},
	"recipientAccountId": "123456789012",
	"requestParameters": null,
	"responseElements": {
		"ConsoleLogin": "Failure"
	},
	"sourceIPAddress": "111.111.111.111",
	"userAgent": "Mozilla",
	"userIdentity": {
		"accountId": "123456789012",
		"arn": "arn:aws:iam::123456789012:user/tester",
		"principalId": "1111",
		"type": "IAMUser",
		"userName": "tester"
	}
}
```



## Test Your Knowledge
This section applies everything we've talked about in the above sections. Use each set of sample data as a unit test and create a corresponding detection based on the prompt. A passing unit test will show the success of your detection. 

**Steps for Each Rule**
1. Create a new rule in the Panther Console
2. Give it a unique name with your initials
3. Under the Functions & Test Tab - scroll to the bottom and create a new unit test
4. Copy and paste the example data for the rule you're working on below
5. Write a Python Rule 
6. Test and Verify

**Rule - AWS CloudTrail - Root Password Change**
- Prompt 1 - Write a detection that triggers an alert when a password is updated 
- Prompt 2 - Add on to the detection to create a check if a "root" password is updated 
- Prompt 3 - 



```
{
	"recipientAccountId": "123456789012",
	"requestParameters": null,
	"responseElements": {
		"PasswordUpdated": "Success"
	},
	"sourceIPAddress": "111.111.111.111",
	"eventName": "PasswordUpdated",
	"eventSource": "signin.amazonaws.com",
	"eventVersion": "1.05",
	"userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
	"eventID": "1111",
	"eventType": "AwsConsoleSignIn",
	"requestID": "1111",
	"userIdentity": {
		"principalId": "123456789012",
		"type": "Root",
		"accesKeyId": "1111",
		"accessKeyId": "",
		"accountId": "123456789012",
		"arn": "arn:aws:iam::123456789012:root"
	},
	"awsRegion": "us-east-1",
	"eventTime": "2019-01-01T00:00:00Z"
}
```
