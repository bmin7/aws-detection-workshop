# Welcome to the Detection-as-Code (DAC) Workshop
This guide will provide you with a step-by-step of all the commands that will be needed during the hands-on portion of the workshop. If you have questions, feel free to ask your group moderator.


## Lesson 1 - Tuning an existing out-of-the-box detection

**Terms we'll reference**
- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)

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



## Exercise 2 - 

**Terms we'll reference**
- [What are Packs?](https://docs.panther.com/writing-detections/detection-packs)


**Exercise 2 Steps**
1. In the Panther Console - Navigate to Build > Packs > Okta Pack
2. Select the Okta.APIKey.Created rule
3. Duplicate your tab 
4. Navigate to Build > Detections > Create New and Create a new rule (Do not clone packed rule)
5. Name the detection a unique name with your initials - Sample "Okta API Key Created - Brandon"
6. Copy and Paste the code from Okta.APIKey.Created Packed Rule
7. Grab the severity function from the templates page or below 
```def severity(event):
    if event.get("field") == "value":
        return "INFO"
    return "HIGH"
```
8. Add the severity function into your detection. Anywhere under the rule function is fine. 
9. Copy over the test event with the sample log event from Okta Sample Data Below
10. Modify the severity function to return a "Low" event when the user is your own email or otherwise return a "High" event (Hint - you will have to use deep_get for this)
11. Test your changes using the unit test
12. Save Changes


**Okta API Key Created Log Event**
```
{
	"debugContext": {},
	"published": "2021-01-08 21:28:34.875",
	"eventType": "system.api_token.create",
	"version": "0",
	"legacyEventType": "api.token.create",
	"outcome": {
		"result": "SUCCESS"
	},
	"request": {},
	"uuid": "2a992f80-d1ad-4f62-900e-8c68bb72a21b",
	"severity": "INFO",
	"displayMessage": "Create API token",
	"actor": {
		"alternateId": "user@example.com",
		"displayName": "Test User",
		"id": "00u3q14ei6KUOm4Xi2p4",
		"type": "User"
	},
	"target": [
		{
			"id": "00Tpki36zlWjhjQ1u2p4",
			"type": "Token",
			"alternateId": "unknown",
			"displayName": "test_key",
			"details": null
		}
	]
}
```





## Exercise 3 - Use Local Developer Centric Workflows when writing detections
Use the Panther Analysis Tool (PAT) with local developer tools to write and test new detections. 


**Terms we'll reference**
- [Panther Analysis Tool](https://docs.panther.com/panther-developer-workflows/panther-analysis-tool#overview)
- [API Key](https://docs.panther.com/panther-developer-workflows/api#how-to-use-panthers-api)


**Exercise 3 Steps**
1. Install Prerequisites on local Machine (Pip, Python3, Git)
2. Install Panther Analysis Tool 
```pip install panther_analysis_tool```
3. Verify proper version (for those of you that have it already, you don't have to update your version)
```panther_analysis_tool --version```
4. Fork off Panther Analysis Tool to local 
```git clone https://github.com/panther-labs/panther-analysis.git```
5. Create API Token in Panther Console - Select the gear on the top right > API Tokens > Create New Token
6. Check permissions for Read Panther Settings Info, Bulk Upload, Manage Policies, Manage Rules, Manage Schedule Queries, View Log Sources, Manage Log Sources
7. Use Check-Connection to verify API setup is successful (This is only on Panther Analysis Tool 0.15.1 and up)
```panther_analysis_tool check-connection --api-host DOMAIN --api-token TOKEN```
7. Create new directory and copy a .py and .yml file
8. Modify .py file and .yml file
9. Test the rule
```panther_analysis_tool test --path <path to rule directory>```
10. Once verified, upload the rule
```panther_analysis_tool upload --path <path to rule> --api-host DOMAIN --api-token TOKEN```
11. Check Panther Console for changes



## Exercise 4 - Enrich a Detection with GreyNoise
Write a detection while using the GreyNoise helper to apply threat intelligence directly into a detection. For this example, we will use a brute force detection with the sample data from Okta below. 

**Terms We Reference**
- [p_enrichment](https://docs.panther.com/enrichment/lookup-tables#write-a-detection-using-lookup-table-data)
- [GreyNoise](https://docs.panther.com/enrichment/greynoise)
- [Lookup Tables](https://docs.panther.com/enrichment/lookup-tables)

**Exercise 4 Steps**
1. Create a new detection in the Panther Console Build > Detections > Create New
2. Name the detection with your initials (Demo GreyNoise Detection Brandon)
3. Select the Okta System Log Type and set a Medium Severity
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


**Sample Okta Event Data for Brute Force Detection**
```
{
	"actor": {
		"alternateId": "admin",
		"displayName": "unknown",
		"id": "unknown",
		"type": "User"
	},
	"client": {
		"ipAddress": "111.111.111.111"
	},
	"eventType": "user.session.start",
	"outcome": {
		"reason": "VERIFICATION_ERROR",
		"result": "FAILURE"
	},
	"p_enrichment": {
		"greynoise_noise_basic": {
			"client.ipAddress": {
				"actor": "EviLCorp",
				"classification": "benign",
				"ip": "1.2.3.4"
			}
		}
	},
	"p_event_time": "2021-06-04 09:59:53.650807",
	"p_log_type": "Okta.SystemLog",
	"p_parse_time": "2021-06-04 10:02:33.650807"
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

**Resources that will help**
- [Documentation](https://docs.panther.com/)
- [Common Helper Functions](https://docs.panther.com/writing-detections/globals#common-helpers)


**Rule 1 - Github New Repository Created**
```
{
	"repo": "my-org/my-repo",
	"actor": "cat",
	"action": "repo.create",
	"created_at": 1621305118553,
	"org": "my-org",
	"p_log_type": "GitHub.Audit"
}
```

- Prompt 1 - Write a detection that fires an alert when a new Github Repository is created by a user 
- Prompt 2 - Create a description and runbook and add it into the alert





**Rule 2 - Box Untrusted Device Access**
```
{
	"created_by": {
		"id": "12345678",
		"type": "user",
		"login": "cat@example",
		"name": "Bob Cat"
	},
	"event_type": "DEVICE_TRUST_CHECK_FAILED",
	"source": {
		"login": "lukeskywalker@starwars.com",
		"id": "12345678",
		"type": "user"
	},
	"type": "event",
	"additional_details": "{\"key\": \"value\"}"
}
```



- Prompt 1 - Write a detection that fires an alert when a user device trust check does not pass
- Prompt 2 - Fire an alert with Info severity when the login user is luke@starwars.com and has a Critical severity alert when the user is vadar@starwars.com. For all other alerts, severity should be Low



**Rule 3 - AWS CloudTrail - Root Password Change**
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


- Prompt 1 - Write a detection that fires off an alert when there is an updated password on a root account 
- Prompt 2 - Add the AWS account ID into the Alert Title 


