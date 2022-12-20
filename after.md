# Answers to the AWS DaC Workshop


## Lesson 1 Answers

**Final Detection**
```
from panther_base_helpers import deep_get

def rule(event):
    return event.get("eventName") == "ConsoleLogin" and deep_get(event,"responseElements","ConsoleLogin") == "Failure"
```

## Lesson 2 Answers

**Severity Function**
```
def severity(event):
    if float(event.get("severity",0)) <= 5.0:
        return "INFO"
    if float(event.get("severity",0)) >= 8.0:
        return "HIGH"
    else:
        return "MEDIUM"
```

**Final Detection**
```
def rule(event):
    return 1.0 <= float(event.get("severity", 0)) <= 10

def severity(event):
    if float(event.get("severity",0)) <= 5.0:
        return "INFO"
    if float(event.get("severity",0)) >= 8.0:
        return "HIGH"
    else:
        return "MEDIUM"
```


## Lesson 3 Answers

**Part 1**
```
def rule(event):
    return event.get("eventName") == "PasswordUpdated"
```

**Part 2**
```
from panther_base_helpers import deep_get

def rule(event):
    if deep_get(event,"userIdentity","type") != "Root":
        return False
     
    if event.get("eventName") == "PasswordUpdated":
        return True
```

**Part 3**
```
from panther_base_helpers import deep_get

def rule(event):
    if deep_get(event,"userIdentity","type") != "Root":
        return False
     
    if event.get("eventName") == "PasswordUpdated":
        return True

def severity(event):
    approved_regions = ["us-east-1","us-east-2"]

    if event.get("awsRegion") in approved_regions:
        return "INFO"
    else:
        return "HIGH"
```
