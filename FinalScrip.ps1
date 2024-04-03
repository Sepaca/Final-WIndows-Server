# Final Scrip
# Sebastian Patino 
# 200528397
#April  17 2024

# Check if the script is running with administrative privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "This script requires administrative privileges. Please run it as an administrator." -ForegroundColor Red
    Exit
}

Import-Module ActiveDirectory

###############################
# menu

# FUnction with the main menu
# Function definition for the Main Menu of the script
function MainMenu {
    # Clear the console window to make the menu easy to read
    Clear-Host

    # Display the Main Menu options with a cyan color for better visibility
    Write-Host "Main Menu - Choose an option:" -ForegroundColor Cyan
    Write-Host "1. Active Directory"
    Write-Host "2. Folder and Shares"
    Write-Host "3. Server Information"
    Write-Host "Q. Quit"

    # Prompt the user to select an option from the menu
    $choice = Read-Host "Select an option (1-3 or Q to quit)"

    # Use a switch statement to handle the user's choice
    switch ($choice) {
        # If the user chooses 1, call the ADMenu function and then return to the main menu
        '1' { ADMenu; MainMenu }
        # If the user chooses 2, call the FolderSharesMenu function and then return to the main menu
        '2' { FolderSharesMenu; MainMenu }
        # If the user chooses 3, call the ServerInfoMenu function and then return to the main menu
        '3' { ServerInfoMenu; MainMenu }
        # If the user chooses Q, exit the function to quit the script
        'Q' { return }
        # If the user enters an invalid option, display a message and show the main menu again
        default { Write-Host "Invalid option, please try again."; MainMenu }
    }
}


# Define a function named WaitForContinue
function WaitForContinue {
    # Prompt the user with a message to press 'C' to continue, displayed in green for visibility
    Write-Host "Press C to continue..." -ForegroundColor Green

    # Start a do-while loop to repeatedly wait for user input
    do {
        # Read user input and store it in the $input variable
        $input = Read-Host
    # Continue looping as long as the user input is not 'C' or 'c'
    # This condition ensures the loop only breaks if the correct key is pressed, making the function case-insensitive
    } while ($input -ne 'C' -and $input -ne 'c')
}

# Define the function ADMenu to display the Active Directory operations menu
function ADMenu {
    # Clear the console to ensure the menu is displayed cleanly
    Clear-Host

    # Print the menu options with a header in cyan for clarity and emphasis
    Write-Host "Active Directory Menu - Choose an option:" -ForegroundColor Cyan
    Write-Host "1. New User"
    Write-Host "2. Change User's Department or Phone Number"
    Write-Host "3. New Security Group"
    Write-Host "4. Update Security Group Membership"
    Write-Host "5. Reset User Password"
    Write-Host "B. Back"

    # Prompt the user to select an option from the menu
    $choice = Read-Host "Select an option (1-5 or B to go back)"

    # Use a switch statement to handle the user's selection
    switch ($choice) {
        '1' { NewUser; WaitForContinue } # Create a new AD user and then wait for user to press 'C' to continue
        '2' { ChangeDepOrPhone; WaitForContinue } # Change an existing user's department or phone number, then wait
        '3' { CreateSecurityGroup; WaitForContinue } # Create a new security group in AD, then wait
        '4' { updateSecurityGruopMem; WaitForContinue } # Update membership of an existing security group, then wait
        '5' { resetUserPssw; WaitForContinue } # Reset a user's password, then wait
        'B' { return } # Go back to the previous menu
        default { Write-Host "Invalid option, please try again."; ADMenu } # Handle invalid input and show menu again
    }
    # Return to the main menu after completing an action or if 'B' is selected
    MainMenu
}



function FolderSharesMenu {
    Clear-Host
    Write-Host "Folder and Shares Menu - Choose an option:" -ForegroundColor Cyan
    Write-Host "1. New Folder"
    Write-Host "2. New Share"
    Write-Host "3. Permissions"
    Write-Host "4. Add Permissions to Folder"
    Write-Host "5. View Existing Permissions on a Folder"
    Write-Host "B. Back"
    $choice = Read-Host "Select an option (1-5 or B to go back)"
    switch ($choice) {
        '1' { newFolder; WaitForContinue }
        '2' { newSharedFolder; WaitForContinue }
        '3' { folderInfoPermissions; WaitForContinue }
        '4' { addFolderPermissions; WaitForContinue }
        '5' { folderInfoPermissions; WaitForContinue }
        'B' { return }
        default { Write-Host "Invalid option, please try again."; FolderSharesMenu }
    }
    MainMenu
}


function ServerInfoMenu {
    Clear-Host
    Write-Host "Server Information Menu - Choose an option:" -ForegroundColor Cyan
    Write-Host "1. Display Server Specs"
    Write-Host "2. Display Resource Information"
    Write-Host "B. Back"
    $choice = Read-Host "Select an option (1-2 or B to go back)"
    switch ($choice) {
        '1' { ServerSpecs; WaitForContinue }
        '2' { ServerResourceInfo; WaitForContinue }
        'B' { return }
        default { Write-Host "Invalid option, please try again."; ServerInfoMenu }
    }
    MainMenu
}



function NewUser {
    # Collect user information
    $firstName = Read-Host "Enter first name"
    $lastName = Read-Host "Enter last name"
    $password = Read-Host -AsSecureString "Enter a password for the user: "

    # Generate user-specific data
    $accountName = "$firstName.$lastName"
    $emailAddress = "$accountName@adatum.com"

    # Display what is going to be created
    Write-Host "Creating user account for $firstName $lastName with Account Name: $accountName and Email: $emailAddress"
    
    # Attempt to create the user account with the provided information
    try {
        New-ADUser -Name $accountName -GivenName $firstName -Surname $lastName -UserPrincipalName $emailAddress -AccountPassword ($password) -Enabled $true -ErrorAction Stop

        # Attempt to retrieve and display the newly created user
        $createdUser = Get-ADUser -Filter "SamAccountName -eq '$accountName'" -ErrorAction Stop
        Write-Host "User created successfully:"
        $createdUser | Format-List Name,SamAccountName,UserPrincipalName
    } catch {
        # Handle errors, for example, if the user already exists or other AD-related issues
        Write-Host "An error occurred creating the user: $_" -ForegroundColor Red
    }
}


function ChangeDepOrPhone {
    # Prompt for the username
    $username = Read-Host "Please enter the username of the AD account you wish to modify"
    
    # Check if user exists
    $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
    if ($null -eq $user) {
        Write-Host "User not found." -ForegroundColor Red
        return
    }
    
    # Choose what detail to update
    $updateChoice = Read-Host "Do you want to update the Department (D) or the Phone number (P)? Enter 'D' or 'P'"
    
    switch ($updateChoice.ToUpper()) {
        'D' {
            # Update Department
            $newDepartment = Read-Host "Enter the new department"
            Set-ADUser -Identity $username -Department $newDepartment
            Write-Host "Department updated for user '$username'." -ForegroundColor Green
        }
        'P' {
            # Update Phone Number
            $newPhone = Read-Host "Enter the new phone number"
            Set-ADUser -Identity $username -OfficePhone $newPhone
            Write-Host "Phone number updated for user '$username'." -ForegroundColor Green
        }
        default {
            Write-Host "Invalid choice. No changes made." -ForegroundColor Yellow
        }
    }
}

function CreateSecurityGroup {
    # Collect group information
    $groupName = Read-Host "Enter the name of the new group"

    # Display the creation of the group
    Write-Host "Creating security group: $groupName"
    
    # Create the security group
    New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security

    # Display confirmation
    $createdGroup = Get-ADGroup -Filter {Name -eq $groupName}
    Write-Host "Security group created successfully:"
    $createdGroup
}

# Defines a function to update membership of a security group in Active Directory
function updateSecurityGruopMem {
    # Prompt the user to enter the username of the AD account they wish to modify
    $UserName = Read-Host "Enter the username of the AD account"

    # Prompt for the name of the security group to which the user will be added or removed
    $GroupName = Read-Host "Enter the name of the security group"
    
    # Ask the user if they want to add or remove the specified user from the specified group
    $Action = Read-Host "Do you want to add or remove the user from the group? (Enter 'Add' or 'Remove')"

    # Use a try-catch block to handle potential errors gracefully
    try {
        # Attempt to retrieve the specified user and group from AD, stopping with an error if not found
        $user = Get-ADUser -Filter "SamAccountName -eq '$UserName'" -ErrorAction Stop
        $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction Stop

        # If the action is to add the user to the group
        if ($Action -eq 'Add') {
            # Use Add-ADGroupMember to add the user to the group
            Add-ADGroupMember -Identity $group -Members $user
            # Confirm the action to the user
            Write-Host "User '$UserName' has been added to group '$GroupName'." -ForegroundColor Green
        }
        # If the action is to remove the user from the group
        elseif ($Action -eq 'Remove') {
            # Use Remove-ADGroupMember to remove the user from the group, without confirmation
            Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
            # Confirm the action to the user
            Write-Host "User '$UserName' has been removed from group '$GroupName'." -ForegroundColor Green
        }
        else {
            # Inform the user if the entered action is not recognized
            Write-Host "Invalid action. Please enter 'Add' or 'Remove'." -ForegroundColor Red
        }
    }
    catch {
        # Catch and display any errors encountered during the process
        Write-Error "An error occurred: $_"
    }
}


# Defines a function to reset a user's password in Active Directory
function resetUserPssw {
    # Prompt the administrator for the username of the AD account whose password needs resetting
    $UserName = Read-Host "Enter the username of the AD account"
    # Securely collect the new password to prevent it from being visible or stored in plain text
    $NewPassword = Read-Host "Enter the new password" -AsSecureString

    # Use a try-catch block for error handling during the password reset process
    try {
        # Reset the user's password. The -Reset flag allows changing the password without knowing the old one.
        # -PassThru returns the modified object, although it's not explicitly used here.
        Set-ADAccountPassword -Identity $UserName -NewPassword $NewPassword -Reset -PassThru

        # Prompt the administrator to decide if the user must change this password at the next logon
        $changeAtLogon = Read-Host "Force user to change password at next logon? (Y/N)"
        if ($changeAtLogon -eq 'Y') {
            # If requested, set the flag to force the user to change the password at the next logon
            Set-ADUser -Identity $UserName -ChangePasswordAtLogon $true
        }

        # Notify the administrator of successful password reset
        Write-Host "Password has been reset successfully for user '$UserName'." -ForegroundColor Green
    }
    catch {
        # Error handling: Display any errors encountered during the process
        Write-Error "An error occurred while resetting the password: $_"
    }
}



function newFolder {
        # Ask for the name of the folder
        $folderName = Read-Host "Enter the name of the new folder"

        # Ask for the location where the folder should be created
        $folderPath = Read-Host "Enter the location where the folder should be created"
    
        # Combine the location and folder name to create the full path
        $fullFolderPath = Join-Path -Path $folderPath -ChildPath $folderName
    
        try {
            # Check if the folder already exists
            if (Test-Path -Path $fullFolderPath) {
                Write-Host "The folder '$folderName' already exists at '$folderPath'." -ForegroundColor Yellow
            } else {
                # Create the folder
                New-Item -Path $fullFolderPath -ItemType Directory
                Write-Host "Folder '$folderName' created at '$folderPath'." -ForegroundColor Green
            }
        } catch {
            Write-Error "An error occurred while creating the folder: $_"
        }
}

function newSharedFolder {
    # Ask for the folder name
    $folderName = Read-Host "Enter the name of the folder you wish to create and share"

    # Ask for the location where the folder will be created
    $folderPath = Read-Host "Enter the full path where the folder will be located"

    # Combine the path and folder name to create the full directory path
    $fullFolderPath = Join-Path -Path $folderPath -ChildPath $folderName

    try {
        # Check if the folder already exists
        if (-Not (Test-Path -Path $fullFolderPath)) {
            # Create the folder
            New-Item -ItemType Directory -Path $fullFolderPath
            Write-Host "Folder '$fullFolderPath' created successfully." -ForegroundColor Green
        } else {
            Write-Host "The folder '$fullFolderPath' already exists." -ForegroundColor Yellow
        }
        
        # Define the share name, which will be the same as the folder name for simplicity
        $shareName = $folderName

        # Share the folder
        New-SmbShare -Name $shareName -Path $fullFolderPath -FullAccess "Everyone"
        Write-Host "Folder '$fullFolderPath' has been shared successfully with the share name '$shareName'." -ForegroundColor Green

    } catch {
        Write-Error "An error occurred: $_"
    }
}

function folderInfoPermissions{
        # Ask for the folder path
        $folderPath = Read-Host "Enter the full path of the folder to view permissions"

        try {
            # Get the ACL for the folder
            $acl = Get-Acl -Path $folderPath
    
            # Output the permissions
            Write-Host "Permissions for '$folderPath':"
            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $permissions = $access.FileSystemRights
                $accessType = $access.AccessControlType
                $inheritance = $access.IsInherited
    
                $output = "Identity: $identity, Permissions: $permissions, Access Type: $accessType, Inherited: $inheritance"
                Write-Host $output
            }
        } catch {
            Write-Error "An error occurred while retrieving folder permissions: $_"
        }
}


function addFolderPermissions {
    # Ask for the folder path
    $folderPath = Read-Host "Enter the full path of the folder to add permissions"

    # Ask for the user or group to which permissions will be added
    $userOrGroup = Read-Host "Enter the user or group for the permissions"

    # Ask for the permissions to be added
    $permissions = Read-Host "Enter the permissions to add (e.g., FullControl, Modify, Read, Write)"

    # Ask for the permission type (Allow or Deny)
    $permissionType = Read-Host "Enter the permission type (Allow or Deny)"

    try {
        # Retrieve the current ACL for the folder
        $acl = Get-Acl -Path $folderPath

        # Create a new file system access rule
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $userOrGroup,
            $permissions,
            'ContainerInherit, ObjectInherit', # This flag sets the rule to be inherited by subfolders and files
            'None', # No inheritance flags
            $permissionType
        )

        # Add the access rule to the ACL
        $acl.AddAccessRule($accessRule)

        # Set the new ACL for the folder
        Set-Acl -Path $folderPath -AclObject $acl

        Write-Host "Permissions added to folder '$folderPath' for user or group '$userOrGroup'." -ForegroundColor Green
    } catch {
        Write-Error "An error occurred while adding permissions: $_"
    }
}
function ServerSpecs {
# Begins the function with a header for clarity in output
    Write-Host "`nComputer Details:"

# Retrieves operating system information using Get-CimInstance and filters it for relevant properties
    $os = Get-CimInstance Win32_OperatingSystem | Select-Object CSName, Caption, Version
# Outputs the operating system details, including its name (Caption), version, and computer name (CSName)
    Write-Host "Operating System: $($os.Caption) - Version: $($os.Version) on $($os.CSName)"

# Gathers total physical memory (RAM) installed on the system and sums it up
    $mem = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
# Converts the total memory from bytes to gigabytes for readability and rounds the result to two decimal places
    $memSum = [math]::round($mem.Sum / 1GB, 2)
# Outputs the total installed memory in GB
Write-Host "Memory: Total Installed: $($memSum) GB"

# Retrieves logical disk information, filtering for disks recognized as "DriveType -EQ 3" (local disks)
    $disks = Get-CimInstance Win32_LogicalDisk | where DriveType -EQ 3 | Select-Object DeviceID, 
        @{Name="Size(GB)";Expression={[math]::round($_.Size / 1GB, 2)}}, # Converts disk size to GB and rounds it
        @{Name="FreeSpace(GB)";Expression={[math]::round($_.FreeSpace / 1GB, 2)}} # Converts free space to GB and rounds it
# Introduces the disk size and available space section
Write-Host "Disk Size and Available Space:"
# Formats the disk information into a table for easy reading, automatically adjusting column widths
$disks | Format-Table -AutoSize

}

function ServerResourceInfo{
# Print a header to introduce the section on resource information
    Write-Host "`nResource Information:"

# Retrieve network adapter configurations, filtering out those without an IP address
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | where IPAddress -ne $null | Select-Object Description, 
        @{Name="IPAddress";Expression={$_.IPAddress[0]}},  # Extract the first IP address if there are multiple
        @{Name="SubnetMask";Expression={$_.IPSubnet[0]}},  # Extract the first subnet mask
        @{Name="Gateway";Expression={$_.DefaultIPGateway[0]}}  # Extract the first gateway if there are multiple
# Display the network adapter details in a table format for easy reading
    Write-Host "Network Adapter Details:"
    $adapters | Format-Table -AutoSize

# Retrieve operating system information to calculate uptime
    $os = Get-CimInstance Win32_OperatingSystem
# Calculate the system's uptime by subtracting the last boot-up time from the current date
    $uptime = New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)
# Display the calculated uptime in days, hours, and minutes
    Write-Host "System Uptime: $($uptime.Days) Days, $($uptime.Hours) Hours, $($uptime.Minutes) Minutes"

# Retrieve the current CPU load for each processor in the system
    $cpuLoad = Get-CimInstance Win32_Processor | Select-Object Name, LoadPercentage
# Display the CPU load information, which includes the name of the CPU and its current utilization percentage
    Write-Host "CPU Current Utilization:"
    $cpuLoad | Format-Table -AutoSize

}


# calling the menu
MainMenu