

function CALogon()  {
    Param( 
        [parameter(Mandatory=$true)] [String] $username,
        [parameter(Mandatory=$false)] [String] $pass,
        [parameter(Mandatory=$true)] [String] $PVWA,
        [parameter(Mandatory=$false)] [Boolean] $ignoreCert = $false, 
        [parameter(Mandatory=$false)] [Boolean] $AskPass = $false
    )
    
    $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    $global:origin=$origin
    $global:CAError=$true
    if(($AskPass -eq $True) -and ($pass -ne "")) {
        return "You cannot use pass and askpass:true at the same time"
    }
    elseif($AskPass -eq $True) {
        $spass=Read-Host "Enter password" -AsSecureString
        $pass=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($spass))
    }


    if ($ignoreCert -eq $true) {

        $certCallback=@"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback
        {
            public static void Ignore()
            {
                if(ServicePointManager.ServerCertificateValidationCallback ==null)
                {
                    ServicePointManager.ServerCertificateValidationCallback += 
                        delegate
                        (
                            Object obj, 
                            X509Certificate certificate, 
                            X509Chain chain, 
                            SslPolicyErrors errors
                        )
                        {
                            return true;
                        };
                }
            }
        }
"@
        Add-Type $certCallback
        [ServerCertificateValidationCallback]::Ignore();
    }

    $body=@{username=$username;
    password=$pass   
    }
    $body=$body | ConvertTo-Json
    $token=""
    $uri=""
    $url="https://" + $PVWA + "/passwordvault/api/auth/cyberark/logon"
    $yer=$url.IndexOf('/api/')
    $uri=$url.substring(0,$yer)
    $global:uri=$uri
    try {
        if ($ignoreCert -eq $true) {
            $global:token =Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/json"  -SkipCertificateCheck
            $global:CAError=$false
        }
        else {
            $global:token =Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/json"
            $global:CAError=$false
        }
        return "Successfully logged in to " + $uri
    }
    catch {
        $errorx="Error Reason: " + $_.ErrorDetails.Message
        $global:CAError=$true
        return $errorx
    }


    
    
}

function CAList() {
    Param( 
        [parameter(Mandatory=$true)] [ValidateSet('Users','Groups','Safes','Accounts','LiveSessions','SafeMembers')] [String] $type,
        [parameter(Mandatory=$false)] [String] $id,
        [parameter(Mandatory=$false)] [ValidateSet($true,$false)] [String] $Activity = $false,
        [parameter(Mandatory=$false)] [String] $SafeUrlId
    )
    try {
        switch($type) {
            "Users" {
                if($id -eq "") {
                    $urlm=$uri + "/api/users"
                    $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                    $list1=$list1.Users | Select-Object id,username
                }
                else {
                    $urlm=$uri + "/api/users/" + $id
                    $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                }
                break
            }
            "Groups" {
                    $urlm=$uri + "/api/UserGroups"
                    $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                    $list1=$list1.Value | Select-Object id,groupname
                break
            }
            "Accounts" {
                if($id -eq "") {
                    $urlm=$uri + "/api/Accounts"
                    $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                    $list1=$list1.Value | Select-Object id,name
                }
                elseif($Activity -eq $true) {
                    $urlm=$uri + "/api/Accounts/" + $id + "/Activities"
                    $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                    $list1=$list1.Activities
                }
                else {
                    $urlm=$uri + "/api/Accounts/" + $id
                    $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                }
                break
            }
            "Safes" {
                $urlm=$uri + "/api/Safes"
                $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                $list1=$list1.Safes | Select-Object SafeUrlId,SafeName 
                break
            }
            "LiveSessions" {
                $urlm=$uri + "/api/LiveSessions"
                $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                break
            }
            "SafeMembers" {
                if ($SafeUrlId -eq "") {
                    return "With type of SafeMembers, you must use SafeUrlID switch."
                }
                else {
                    $urlm=$uri + "/api/Safes/" + $SafeUrlId + "/Members"
                    $list1=Invoke-RestMethod -Method Get -Uri $urlm -ContentType "application/json"  -Headers @{"Authorization"=$token} -SkipCertificateCheck
                    $list1=$list1.SafeMembers 
                }
                break
            }
        }
        $global:CAError=$false
    }
    catch {
        $errorx="Error Reason: " + $_.Exception.response.ReasonPhrase  
        $global:CAError=$true
        return $errorx
        
    }
    

    return $list1

}

function CACreateTable() {
    Param( 
        [parameter(Mandatory=$true)] [ValidateSet('Permission','AccountActivity')] [String] $type
    )
    switch($type) {
        "Permission" {
            $perms=@("UseAccounts",
            "RetrieveAccounts",
            "ListAccounts",
            "AddAccounts",
            "UpdateAccountContent",
            "UpdateAccountProperties",
            "InitiateCPMAccountManagementOperations",
            "SpecifyNextAccountContent",
            "RenameAccounts",
            "DeleteAccounts",
            "UnlockAccounts",
            "ManageSafe",
            "ManageSafeMembers",
            "BackupSafe",
            "ViewAuditLog",
            "ViewSafeMembers",
            "AccessWithoutConfirmation",
            "CreateFolders",
            "DeleteFolders",
            "MoveAccountsAndFolders",
            "RequestsAuthorizationLevel1",
            "RequestsAuthorizationLevel2")
        
            $tbl = New-Object System.Data.DataTable "Members-Permissions"
            $col = New-Object System.Data.DataColumn Safe
            $tbl.Columns.Add($col)
            $col = New-Object System.Data.DataColumn "Member"
            $tbl.Columns.Add($col)
            $col = New-Object System.Data.DataColumn "Predifined"
            $tbl.Columns.Add($col)
            foreach($perm in $perms) {
                $col = New-Object System.Data.DataColumn $perm
                $tbl.Columns.Add($col)
            }
        }
        "AccountActivity" {
            $cols=@("Account",
            "Safe",
            "DateIn",
            "DateOut",
            "Duration",
            "SourceAddr",
            "SourceUser",
            "PSM",
            "AccountAddr",
            "AccountUser",
            "Protocol",
            "SessionID")
            $tbl = New-Object System.Data.DataTable "AccountActivities"
            foreach($colx in $cols) {
                $col = New-Object System.Data.DataColumn $colx
                $tbl.Columns.Add($col)
            }
            break
        }
    }
    return ,$tbl
}


function CAGetPermissionsTable() {
    Param( 
        [parameter(Mandatory=$false)] [String] $Export2CSV
    )

    $tbl=CACreateTable -type "Permission"
    $Safes=CAList -type Safes
    foreach($Safe in $Safes) {
        $Perms=CAList -type SafeMembers -SafeUrlId $Safe.SafeUrlId
        foreach($Perm in $Perms) {
            $row = $tbl.NewRow()
            $row.Safe = $Safe.SafeName
            $row.Member=$Perm.MemberName
            $row.Predifined=$Perm.IsPredefinedUser
            foreach ($p in $Perm.Permissions.PSObject.Properties) {
                $row.($p.Name)=$p.value
            }
            $tbl.Rows.Add($row)

        }
    }
    if($Export2CSV -eq "") {
      return ,$tbl  
    }
    else{
        $tbl | Export-Csv -path $Export2CSV -NoTypeInformation
    }
    
}


function CAInfo2HashTable($Infos) {
    $Infos=$Infos.Split(",")
    $hashtable = @{}
    foreach($Info in $Infos) {
        $Ins=$Info.Split(":")
        if($Ins[0].Trim() -eq "Session Duration") {
            $Sdr=""
            for($i=1;$i -lt $Ins.count;$i++) {
                $Sdr=$Sdr + ":" + $Ins[$i].trim() 
            }
            $Sdr=$Sdr.Substring(1)
            $hashtable.Add($Ins[0].Trim(),$Sdr)
        }
        else{
            $hashtable.Add($Ins[0].Trim(),$Ins[1].Trim())
        }
        
    }
    return $hashtable
}

function CAGetAccountUseDetails() {
    Param( 
        [parameter(Mandatory=$false)] [String] $Export2CSV,
        [parameter(Mandatory=$true)] [String] $id
    )
    $tbl=CACreateTable -type "AccountActivity"
    $Activities=CAList -type Accounts -id $id -Activity:$true
    if($CAError -eq $true) {
        return "You must login to the PVWA."
    }
    $AccountInfo=CAList -type Accounts -id $id
    $Connects=$Activities | Where-Object { $_.Action -eq "PSM Connect" }
    foreach ($connect in $Connects) {
        $row = $tbl.NewRow()
        $row.Account=$AccountInfo.Name
        $row.Safe=$AccountInfo.safeName
        $row.AccountAddr=$AccountInfo.address
        $row.AccountUser=$AccountInfo.Username
        $hash1=CAInfo2HashTable($connect.MoreInfo)
        $row.SessionID=$hash1['Session ID']
        $row.Protocol=$hash1['Protocol']
        $row.SourceAddr=$hash1['Source Address']
        $row.SourceUser=$Connect.User
        $row.DateIn=$Connect.Date
        $row.PSM=$hash1['PSM Server']
        $tbl.Rows.Add($row)
    }

    $DisConnects=$Activities | Where-Object { $_.Action -eq "PSM Disconnect" }
    foreach ($disconnect in $DisConnects) {
        $hash2=CAInfo2HashTable($disconnect.MoreInfo)
        $tbl | where-object {$_.SessionID -eq $hash2['Session ID']} | foreach-object {$_.Duration=$disConnect.Date-$_.DateIn;$_.DateOut=$origin.AddSeconds($disConnect.Date);$_.DateIn=$origin.AddSeconds($_.DateIn)}
    }
    $tbl | where-object {$_.DateOut.GetType().Name -eq "DBNull" } | foreach-object {$_.DateIn=$origin.AddSeconds($_.DateIn)}
       
    
    if($Export2CSV -eq "") {
        return ,$tbl  
      }
      else{
          $tbl | Export-Csv -path $Export2CSV -NoTypeInformation
      }

}



function CAGetUserUseDetails() {
    Param( 
        [parameter(Mandatory=$false)] [String] $Export2CSV,
        [parameter(Mandatory=$true)] [String] $user
    )
    $tbl=CACreateTable -type "AccountActivity"
    $Accounts=CAList -type Accounts
    if($CAError -eq $true) {
        return "You must login to the PVWA."
    }
    foreach($Account in $Accounts) {
        $Activities=CAList -type Accounts -id $Account.id -Activity:$true
        $AccountInfo=CAList -type Accounts -id $Account.id 
        $Connects=$Activities | Where-Object { $_.Action -eq "PSM Connect" }
        foreach ($connect in $Connects) {
            $row = $tbl.NewRow()
            $row.Account=$AccountInfo.Name
            $row.Safe=$AccountInfo.safeName
            $row.AccountAddr=$AccountInfo.address
            $row.AccountUser=$AccountInfo.Username
            $hash1=CAInfo2HashTable($connect.MoreInfo)
            $row.SessionID=$hash1['Session ID']
            $row.Protocol=$hash1['Protocol']
            $row.SourceAddr=$hash1['Source Address']
            $row.SourceUser=$Connect.User
            $row.DateIn=$Connect.Date
            $row.PSM=$hash1['PSM Server']
            $tbl.Rows.Add($row)
        }
    
        $DisConnects=$Activities | Where-Object { $_.Action -eq "PSM Disconnect" }
        foreach ($disconnect in $DisConnects) {
            $hash2=CAInfo2HashTable($disconnect.MoreInfo)
            $tbl | where-object {$_.SessionID -eq $hash2['Session ID']} | foreach-object {$_.Duration=$disConnect.Date-$_.DateIn;$_.DateOut=$origin.AddSeconds($disConnect.Date);$_.DateIn=$origin.AddSeconds($_.DateIn)}
        }
        $tbl | where-object {$_.DateOut.GetType().Name -eq "DBNull" } | foreach-object {$_.DateIn=$origin.AddSeconds($_.DateIn)}
    }
    $tbl=$tbl | where-object {$_.SourceUser -eq $user }

    if($Export2CSV -eq "") {
        return ,$tbl  
      }
      else{
          $tbl | Export-Csv -path $Export2CSV -NoTypeInformation
      }



}