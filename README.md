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

CALogon -username JohnDoe -pass mypass -PVWA 1.1.1.1 -ignorecert $true       # Logon and create a token.

CALogon -username JohnDoe -AskPass -PVWA 1.1.1.1                             # Ask for password.

### CAList

Lists 'Users','Groups','Safes','Accounts','LiveSessions','SafeMembers' with ids.

#### Switches

**type       :** Selects listing objects. Acceptable values are 'Users','Groups','Safes','Accounts','LiveSessions','SafeMembers'. Required.

**id         :** Works with Users and Accounts type. Give details about account or user. Optional.

**Activity   :** Works with Account type and Account id. If Actvity and Account id set as true, gives activities of selected account. 

**SafeUrlId  :** Works with safemember type. 

#### Example

CAList -type Users                                                           # Lists Users with ids.

CAList -type Accounts -id 37_3                                               # Lists Account properties with Account id 37_3.

CAList -type Accounts -id 37_3 -Activity $true                               # Lists Account activities with Account id 37_3.

CAList -type SafeMembers -SafeUrlId Safe1                                    # Lists Safe1 safe members.

### CACreatePermissionTable

Just create a permission table template for permissions. Tested for Cyberark PAS 11.2.

#### Switches

**type       :** Specify table type to be created. Acceptable values are 'Permission','AccountActivity'. Required.

#### Example

CAGetPermissionsTable -type AccountActivity                                  # Creates AccountActivity table template.

### CAGetPermissionsTable

Creates a table, which lists permissions for safe users.

#### Switches

**Export2CSV :** After the switch specify the path of the csv file.

#### Example

CAGetPermissionsTable -Export2CSV c:\test\perms.csv

### CAInfo2HashTable

This function converts Activities' moreInfo string value to hash table. 

#### Switches

**Infos      :** After the switch you can specify the csv file path to be exported.

#### Example

CAInfo2HashTable -Infos $Activity.moreInfo

### CAGetAccountUseDetails

Lists the activities of CyberArk Accounts like who logged in,when logged in and logged out, duration etc.

#### Switches

**Export2CSV :** After the switch specify the path of the csv file. Optional.

**id         :** id of the Account. You can get it ids from 'CAList -type Accounts'. Required.

#### Example

CAGetAccountUseDetails -id 33_2                                              # Lists activities on account with id.

### CAGetUserUseDetails

Lists the activities of users like who logged in,when logged in and logged out, duration etc.

#### Switches

**Export2CSV :** After the switch specify the path of the csv file. Optional.

**user       :** id of the Account. You can get it ids from 'CAList -type Accounts'. Required.

#### Example

CAGetAccountUseDetails -id john.doe                                           # Lists activities on account with username.  




