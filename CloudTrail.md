## MITRE ATT&CK for Detection-as-Code Workshop ##

**Helpful Links**
- [All Available Rule Functions](https://github.com/panther-labs/panther-analysis/blob/master/templates/example_rule.py)
- [API Key](https://docs.panther.com/panther-developer-workflows/api#how-to-use-panthers-api)
- [Lookup Tables](https://docs.panther.com/enrichment/lookup-tables)
- [Panther Analysis Tool](https://docs.panther.com/panther-developer-workflows/panther-analysis-tool#overview)
- [Unit Tests](https://docs.panther.com/writing-detections/testing#mocks)
- [What is Deep_Get?](https://docs.panther.com/writing-detections/globals#deep_get)
- [What are Packs?](https://docs.panther.com/writing-detections/detection-packs)


Do we add a section for ingesting data??



## Lesson 1 - Writing A Detection with Python

**Part 1 - Setup Detection in Console**
1. In the Panther Console - Navigate to Build > Detections > Create New
2. Give it a unique name "Brandon's First Detection" (Use your own name or initials)
3. Set Severity to "Medium" and Log Types "AWS.CloudTrail"
4. Under the Functions & Test Tab, Scroll down and select the "Create Test" button
5. Copy and Paste the Sample CloudTrail Log from Below into the Test Field

**Part 2 - Writing Python**
1. COME UP WITH A DETECTION TO WRITE


## Lesson 2 - Modify Detection

**Part 1 - Code Reuse**
1. Let's take the detection we just wrote and apply it to another AWS resource. 



## Lesson 3 - Down the Killchain

**Part 1 - Select the next 3 tactics**
1. Write more detections and verify the accuracy of each one


## Lesson 4 - Detection Engineering 
1. 



3. Detection Building 
- Preparation - Ingest and Query Data - Panther Value - Ingest Quickly and Easily
- Writing - Python Tools and Open-Source Help
- Testing - Unit Tests (maybe Data Replay)
- Deployment - CI/CD Pipeline 

4. Deploying Detections 




