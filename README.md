# simpleCyberarkTasks

This project aims to simplify CyberArk Priviliged Access Security restAPI procedures via Powershell. 

## Tested For

CyberArk Privileged Access Security 11.2
Powershell 7.1.2

## Usage

### CALogon

Creates an access token.

#### Switches

**username   :** The username who can access restAPI services. Required.

**PVWA       :** PVWA server which serves as restAPI service. Required.

**pass       :** Username's password. You can specify password after that switch. You cannot use pass switch with AskPass switch.

**AskPass    :** Set AskPass as $true if you dont want to write the password clear.  You cannot use pass switch with AskPass switch.

**ignoreCert :** If you are not using trusted certificate or specify PVWA as IP set this switch as true. Optional.

#### Example

CALogon -username JohnDoe -pass mypass -PVWA 1.1.1.1 -ignorecert $true

CALogon -username JohnDoe -AskPass -PVWA 1.1.1.1


