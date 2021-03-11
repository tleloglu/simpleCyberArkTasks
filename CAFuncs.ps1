

function CALogon()  {
    Param( 
        [parameter(Mandatory=$true)] [String] $username,
        [parameter(Mandatory=$false)] [String] $pass,
        [parameter(Mandatory=$true)] [String] $PVWA,
        [parameter(Mandatory=$false)] [Boolean] $ignoreCert = $false, 
        [parameter(Mandatory=$false)] [Boolean] $AskPass = $false
    )
    
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
    if ($ignoreCert -eq $true) {
        $global:token =Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/json"  -SkipCertificateCheck
    }
    else {
        $global:token =Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/json"
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
    }
    catch {
        $errorx="Error Reason: " + $_.Exception.response.ReasonPhrase  
        return $errorx
        
    }
    

    return $list1

}

function CACreatePermissionTable() {
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

    return ,$tbl

}


function CAGetPermissionsTable() {
    $tbl=CACreatePermissionTable
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
    return $tbl
}

function CAGetPermissionsTableCSV() {
    $tbl=CAGetPermissionsTable
    $tbl | Export-Csv -path .\test.csv -NoTypeInformation
}
