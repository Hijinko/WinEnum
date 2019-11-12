###########################################################################
#
# Title: Enumerate Baseline
# Filename: WinEnum.ps1
# Creator: SGT Ellis, Kevin
# Version: 2
# Date: 20190529
# Description: Program creates a baseline enumeration of a windows system
#              including some persistence registry keys, and allows the user
#              to compare baselines from different dates. Program is useful
#              for both offensive and defensive missions
#
#########################################################################

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole))
   {
   # We are running "as Administrator" - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
   }
else
   {
   # We are not running "as Administrator" - so relaunch as administrator
   
   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   
   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   
   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";
   
   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);
   
   # Exit from the current, unelevated, process
   exit
   }
 
# Run your code that needs to be elevated here
# define a variable that is the homepath of the current user
    $p = $env:HOMEPATH

<# define a function to enumerate the target and output the reults to a file
function takes in one parameter ($outfile) as a name of a file #>
function Enumerate($outfile){

    # define a variable that is the homepath of the current user
    #$p = $env:HOMEPATH

    # get the date
    Get-Date | Out-File $p\$outfile

    # get the hostname
    $env:COMPUTERNAME | Out-File -Append $p\$outfile

    # get users
    Get-LocalUser | Select-Object name, enabled, sid | Out-File -Append $p\$outfile

    # get the groups and their members and display only user objects
    Get-LocalGroup `
    | foreach {Write-Output `n $_.name $(Get-LocalGroupMember $_.name | Where-Object {$_.objectclass -imatch "user"} `
    | Select-Object Name, PrincipalSource ) `n **********************************} `
    | Out-File -Append $p\$outfile

    # get the currently logged in users by querying who owns current running processes
    $(Get-WmiObject win32_process).getowner() | Select-Object user | Sort-Object user -Unique | Out-File -Append $p\$outfile

    # get the currently running processes and their session id
    Get-Process | Select-Object name, si, id | sort -Property id | Out-File -Append $p\$outfile

    #get the services and their states
    Get-Service | Select-Object status, name | Out-File -Append $p\$outfile

    # get network information
    Get-NetIPConfiguration | Out-File -Append $p\$outfile

    # get listening network sockets
    Get-NetTCPConnection -State Listen `
    | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess `
    | sort -Property OwningProcess `
    | Format-Table | Out-File -Append $p\$outfile

    # get Established network sockets
    Get-NetTCPConnection -State Established `
    | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess `
    | sort -Property OwningProcess `
    | Format-Table | Out-File -Append $p\$outfile

    # get system configuration information
    Get-ComputerInfo | Out-File -Append $p\$outfile

    # get the mapped drives
    Get-PSDrive | Select-Object name | Out-File -Append $p\$outfile

    # get plug and play devices
    Get-PnpDevice | Select-Object status, class, name | Out-File -Append $p\$outfile

    # get shared resorces
    Get-SmbShare | Out-File -Append $p\$outfile

    # get scheduled tasks
    Get-ScheduledJob | Out-File -Append $p\$outfile
}

# function will get the content of some forensically significant registries and some
# persestence regestries.
Function Get-regshot($outfile){
    $sids = @()
    Get-ChildItem HKU: | ForEach-Object {$sids += $_} #array holds the sid of each user under HKU:
    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | format-list >> $p\$outfile 
    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce | format-list >> $p\$outfile 
    $(foreach ($sid in $sids){Get-ItemProperty -ErrorAction SilentlyContinue HKU:\$sid\Software\Microsoft\Windows\CurrentVersion}) | format-list >> $p\$outfile
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" | format-list >> $p\$outfile 
    Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services | format-list >> $p\$outfile
    Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USB | format-list >> $p\$outfile
    $(foreach ($sid in $sids){Get-ItemProperty -ErrorAction SilentlyContinue "HKU:\$sid\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"}) | format-list>> $p\$outfile
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\" | format-list >> $p\$outfile
    Get-ChildItem -Recurse -ErrorAction SilentlyContinue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" | Format-List >> $p\$outfile
    Get-ItemProperty HKLM:\BCD00000000 | format-list>> $p\$outfile
    }

# create a menu that gives the user options to either enumerate or run comparison of last enumeration
$looping = $true # variable makes sure the menu continues to display until the user wants to quit
While ($looping){ 
    Clear-Host
    $userChoice = ""

    # start menu
    Write-Host "[E]numerate"
    Write-Host "[C]ompare"
    Write-Host "[T]rack Cover"
    Write-Host "[Q]uit"
    $userChoice = Read-Host

    # user wants to enumerate a new target
    if ($userChoice -ieq "e"){ 
        $base = Read-Host "What do you want to name the baseline?" # allows the user to name the outfile whatever they want
        if(-not ($base -imatch '.txt$')){$base = $base + ".txt"} # makes sure the file is a .txt file
        Enumerate $base
        Get-regshot $base
        #Set-ItemProperty -Path $env:HOMEPATH\$base -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) # makes the file hidden, good for offensive operations
        Clear-Host
        Write-Host "Enumeration complete: $base"
        Start-Sleep -Seconds 2
    }

    # user wants to compare two baselines
    elseif($userChoice -ieq "c"){ 
        $Fbase = Read-Host "What is the name of the first baseline?" # gets the name of the first baseline to compare to
        if(-not ($Fbase -imatch '.txt$')){$Fbase = $Fbase + ".txt"} # makes sure the file is a .txt file
        if (Test-Path $env:HOMEPATH\$Fbase){ #check to see if the file actually exists
            $Sbase = Read-Host "What is the name of the second baseline?"
            if(-not ($Sbase -imatch '.txt$')){$Sbase = $Sbase + ".txt"} # makes sure the file is a .txt file
            if (Test-Path $env:HOMEPATH\$Sbase){
                Compare-Object $(Get-Content $env:HOMEPATH\$Sbase) $(Get-Content $env:HOMEPATH\$Fbase) | Out-File $env:HOMEPATH\compfile.txt
                (Get-Content $env:HOMEPATH\compfile.txt) -replace '<=', "New in $Sbase" | Set-Content $env:HOMEPATH\compfile.txt 
                Get-Content $env:HOMEPATH\compfile.txt # displays the comparison in terminal
                #Write-Host "***Key: (=> only in $Fbase) (<= only in $Sbase)***"
                Read-Host "Press [ENTER] to continue" # will allow the terminal to keep the changes until the user is done analyzing them 
            }
            else{ # if the user provided filename for $Sbase that does not exist, display an error message and return to main menu
                Write-Output "Baseline named [$Sbase] does not exist. Returning to main menu"
                Start-Sleep -Seconds 3
            }
        }
        else{ # if the user provided filename for $Fbase does not exist, display an error message and return to main menu
            Write-Output "Baseline named [$Fbase] does not exist. Returning to main menu"
            Start-Sleep -Seconds 3
        }    
    }

    # user wants to delete created files
    elseif($userChoice -ieq "t"){ 
        Remove-Item $env:HOMEPATH\$Sbase -ErrorAction SilentlyContinue
        Remove-Item $env:HOMEPATH\$Fbase -ErrorAction SilentlyContinue
        Remove-Item $env:HOMEPATH\compfile.txt -ErrorAction SilentlyContinue
        Write-Host "The Following files have been deleted; $Sbase, $Fbase, and compfile.com"

        while ($true){ # allows the user to delete other files the program may have missed 
            Write-Host "If you have additional files to delete, please enter the full path now or press [q] to return to main menu"
            $RemoveAnother = Read-Host # gets the filepath of the file to delete
            if ($removeAnother -ieq "q"){break} #exits the loop if the user is done removing files
            Remove-Item $RemoveAnother -ErrorAction SilentlyContinue
        }
    }

    # user wants to quit the program
    elseif($userChoice -ieq "q"){
        $looping = $false
        Clear-Host
    }

    # if user pics invalid choice than display error message and prompt again
    else{ 
        Write-Host "****Error: Invalid input [$userChoice], please select [E], [C], or [Q]****"
        Start-Sleep -Seconds 4
    }

}
