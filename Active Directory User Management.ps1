# Import Active Directory module
Import-Module ActiveDirectory

# Function to create a new user in Active Directory
function CreateUser {
    param (
        [string]$UserName,
        [string]$FirstName,
        [string]$LastName,
        [string]$Password,
        [string]$OU = "OU=Users,DC=domain,DC=com" # Change this to your OU
    )

    # Construct the user principal name and display name
    $UserPrincipalName = "$UserName@domain.com"
    $DisplayName = "$FirstName $LastName"

    # Create the user
    New-ADUser `
        -SamAccountName $UserName `
        -UserPrincipalName $UserPrincipalName `
        -Name $DisplayName `
        -GivenName $FirstName `
        -Surname $LastName `
        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
        -Enabled $true `
        -Path $OU `
        -PasswordNeverExpires $false `
        -ChangePasswordAtLogon $true

    # Enable the user account
    Enable-ADAccount -Identity $UserName

    Write-Output "User $DisplayName created successfully."
}

# Function to delete a user from Active Directory
function DeleteUser {
    param (
        [string]$UserName
    )

    # Delete the user
    Remove-ADUser -Identity $UserName -Confirm:$false

    Write-Output "User $UserName deleted successfully."
}

# Function to reset a user's password
function ResetPassword {
    param (
        [string]$UserName,
        [string]$NewPassword
    )

    # Reset the user's password
    Set-ADAccountPassword -Identity $UserName -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force) -Reset

    # Force the user to change the password at next logon
    Set-ADUser -Identity $UserName -ChangePasswordAtLogon $true

    Write-Output "Password for user $UserName has been reset successfully."
}

# Function to disable inactive accounts
function DisableInactiveAccounts {
    param (
        [int]$DaysInactive = 90 # Number of days of inactivity
    )

    # Get the date for the inactivity threshold
    $InactivityThreshold = (Get-Date).AddDays(-$DaysInactive)

    # Find inactive user accounts
    $InactiveAccounts = Get-ADUser -Filter {LastLogonDate -lt $InactivityThreshold} -Properties LastLogonDate

    foreach ($Account in $InactiveAccounts) {
        Disable-ADAccount -Identity $Account.SamAccountName
        Write-Output "User account $($Account.SamAccountName) has been disabled due to inactivity."
    }
}

# Function to add a user to a security group
function AddUserToGroup {
    param (
        [string]$UserName,
        [string]$GroupName
    )

    # Add the user to the group
    Add-ADGroupMember -Identity $GroupName -Members $UserName

    Write-Output "User $UserName has been added to group $GroupName."
}

# Function to remove a user from a security group
function RemoveUserFromGroup {
    param (
        [string]$UserName,
        [string]$GroupName
    )

    # Remove the user from the group
    Remove-ADGroupMember -Identity $GroupName -Members $UserName -Confirm:$false

    Write-Output "User $UserName has been removed from group $GroupName."
}

# Example usage of the functions
# Uncomment the following lines to use the script

# Create a new user
# CreateUser -UserName "jroe" -FirstName "Jack" -LastName "Roe" -Password "P@ssw0rd123"

# Delete an existing user
# DeleteUser -UserName "jroe"

# Reset a user's password
# ResetPassword -UserName "jroe" -NewPassword "R3s3TP@ssw0rd123"

# Disable inactive accounts
# DisableInactiveAccounts -DaysInactive 90

# Add a user to a security group
# AddUserToGroup -UserName "jroe" -GroupName "ITSupport"

# Remove a user from a security group
# RemoveUserFromGroup -UserName "jroe" -GroupName "ITSupport"
