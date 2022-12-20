# Welcome to the Detection-as-Code (DAC) Workshop
This guide will provide you with a step-by-step of all the commands that will be needed during the hands-on portion of the workshop. If you have questions, feel free to ask your group moderator.

**Helpful Links**
- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)
- [What are Packs?](https://docs.panther.com/writing-detections/detection-packs)
- [Panther Analysis Tool](https://docs.panther.com/panther-developer-workflows/panther-analysis-tool#overview)
- [Lookup Tables](https://docs.panther.com/enrichment/lookup-tables)
- [Unit Tests](https://docs.panther.com/writing-detections/testing#mocks)
- [Panther Analysis Tool](https://docs.panther.com/panther-developer-workflows/panther-analysis-tool#overview)
- [API Key](https://docs.panther.com/panther-developer-workflows/api#how-to-use-panthers-api)



## Lesson 1 - Writing a Detection for CloudTrail IAM Logs

**Part 1 - Prepare Detection Writing**
1. In the Panther Console - Navigate to Build > Detections > Create New
2. Give it a unique name "Brandon's Failed Login IAM Detection" (Use your own name or initials)
3. Set Severity to "Medium" and Log Types "AWS.CloudTrail"

**Part 2 - Create Unit Test**
1. Select "Functions and Tests" in the tab below
2. Scroll down and select the "Create Test" button
3. Delete the brackets populated. Copy and paste the sample event below into your console

**CloudTrail IAM Sample Log**
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
**Part 3 - Writing your detection code**

1. Import deep_get function from the panther_base_helpers library ```from panther_base_helpers import deep_get```
2. All rules require a "rule" function that is a boolean to trigger an alert - True fires and alert 
3. Create a rule function with ```def rule(event)```
4. To write the rule, identify the event attributes that associate with a failed login. This should be "eventName" and "ConsoleLogin"
5. Using event.get and deep_get to grab attributes from the event log, write a return statement that is TRUE when a console login attempt fails







## Lesson 2 - Tune an Existing GuardDuty Detection created by Panther


**Part 1 - Clone a Managed Detection**
1. In the Panther Console - Navigate to Build > Packs > Panther Core AWS Pack
2. Select the AWS GuardDuty High Severity Finding
3. Select Clone & Edit on the Top Right | IF you're using a shared dev instance, please copy & paste detection to a new one. Do NOT clone & edit to avoid merge conflicts

**Part 2 - Prepare Unit Test**

1. Name the detection a unique name with your initials - Sample "AWS GuardDuty High Severity Finding - Brandon"
2. Select Functions & Tests
3. Scroll down and populate test with log if not already done

**CloudTrail GuardDuty Log**
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




**Part 3 - Tune Detection with Severity Function**
1. Capture all guardduty detections as alerts in Panther, but tune out the lower end ones. 
2. Modify the rule function to alert on events from severity 1 to 10
3. To reduce noise of this detection, use the severity function to create dynamic categorization of alerts
4. Use an IF statement to send severity 5 and below alerts to "INFO" level and 8 and above to "HIGH". For any other severity, return "MEDIUM"

## Lesson 3 - Upload Detections with Panther_Analysis_Tool

**Part 1 - Create API Token**
1. Within the Panther Console, select the gear icon on the top right > API Tokens
2. Create a new token with all privileges 
3. Save the value for later


**Part 2 - Install PreReqs**
1. Local machine will need Pip, Python3, and Git installed 

**Part 3 - Install Panther Analysis Tool**
1. Here is the link to the [PAT Repo](https://github.com/panther-labs/panther-analysis)
2. Install PAT with Pip ```pip3 install panther_analysis_tool```
3. Check Version ```panther_analysis_tool --version```
4. Verify API Token and PAT Connection ```panther_analysis_tool check-connection --api-host DOMAIN --api-token TOKEN```

**Part 4 - Clone Repo**
1. Use Git to clone the Panther Analysis Repo ```git clone https://github.com/panther-labs/panther-analysis.git```
2. Verify clone in files


**Part 5 - Modify and Upload a Detection**
1. Create a new directory in Panther Analysis and copy .py and .yml file
2. Modify both files 
3. Test the new Rule - ```panther_analysis_tool test --path <path to rule directory>```
4. Upload the Rule - ```panther_analysis_tool upload --path <path to rule> --api-host DOMAIN --api-token TOKEN```







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
- Prompt 3 - Trigger an "INFO" level alert if the AWS region is "us-east-1 or us-east-2" otherwise trigger a "HIGH" level alert. 



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
