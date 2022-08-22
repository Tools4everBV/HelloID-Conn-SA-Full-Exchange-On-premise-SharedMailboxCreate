$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$alias = $form.naming.alias 
$commonname = $form.naming.commonname
$upn = $form.naming.userPrincipalName

<#----- Exchange On-Premises: Start -----#>
# Connect to Exchange
try{
    $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername,$adminSecurePassword
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop 
    #-AllowRedirection
    $null = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber
    Write-Information "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" 
    
    $Log = @{
            Action            = "CreateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
} catch {
    Write-Error "Error connecting to Exchange using the URI [$exchangeConnectionUri]. Error: $($_.Exception.Message)"
    $Log = @{
            Action            = "CreateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Failed to connect to Exchange using the URI [$exchangeConnectionUri]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}

Function GenerateStrongPassword ([Parameter(Mandatory=$true)][int]$PasswordLenght)
{
    Add-Type -AssemblyName System.Web
    $PassComplexCheck = $false
    do 
    {
        $newPassword=[System.Web.Security.Membership]::GeneratePassword($PasswordLenght,1)
        If ( ($newPassword -cmatch "[A-Z\p{Lu}\s]") `
        -and ($newPassword -cmatch "[a-z\p{Ll}\s]") `
        -and ($newPassword -match "[\d]") `
        -and ($newPassword -match "[^\w]")
        )
        {
            $PassComplexCheck=$True
        }
    } While ($PassComplexCheck -eq $false)
    return $newPassword
}

# Create mailbox
try{
    $password = GenerateStrongPassword(22)
    
    $exchangeMailboxParams = @{
        Name             = $commonname
        Alias            = $alias
        UserPrincipalName= $upn
        OrganizationalUnit = $ADsharedMailboxOU
        Password = (ConvertTo-SecureString -AsPlainText $password -Force)
    }
    
    $mailbox = New-Mailbox @exchangeMailboxParams -Shared -ErrorAction Stop
    Write-Information "Successfully created shared mailbox for $commonname." 
    
    $Log = @{
            Action            = "CreateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Successfully created shared mailbox for $commonname." # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $commonname # optional (free format text) 
            TargetIdentifier  = $([string]$mailbox.Guid) # optional (free format text) 
        }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
    
    
}catch{
    Write-Error "Error creating shared mailbox for $commonname.  Error: $($_.Exception.Message)"
    $Log = @{
            Action            = "CreateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Error creating shared mailbox for $commonname." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $commonname # optional (free format text) 
            TargetIdentifier  = $([string]$mailbox.SID) # optional (free format text) 
        }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
    
}


# Disconnect from Exchange
try{
    Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]"     
    $Log = @{
            Action            = "CreateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
} catch {
    Write-Error "Error disconnecting from Exchange.  Error: $($_.Exception.Message)"
    $Log = @{
            Action            = "CreateResource" # optional. ENUM (undefined = default) 
            System            = "Exchange On-Premise" # optional (free format text) 
            Message           = "Failed to disconnect from Exchange using the URI [$exchangeConnectionUri]." # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
        }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
<#----- Exchange On-Premises: End -----#>
