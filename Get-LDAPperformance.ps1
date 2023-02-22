## Get-LDAPperformance - LDAP query performance events analysis
# Collects LDAP Query Performance Events and analyzes them to CSV & Grid. Helps in identifying large or unusual LDAP queries, either for Threat Hunting or IT optimization.
# NOTE: No Dependencies. No modules required. Requires Event Log Readers permission or equivalent (privileged/access to DC 'directory Services' logs)
## by 1nTh35h311 (comments to yossis@protonmail.com)

# 1. First, you need to enable 'DS Access - Directory Services Access' in GPO for auditing
# 2. If the following Reg Key does not exist locally on all Domain Controllers - please create it:
# Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics -Name "15 Field Engineering" -Value 5
# NOTE: to stop logging these events in "Directory Services" Log, set the registry key value to 0

$DCs = ([adsisearcher]"(&(objectCategory=computer)(|(primarygroupid=521)(primarygroupid=516)))").FindAll().Properties.name;
$i = 1;
[int]$NumOfDCs = ($DCs |Measure-Object).count;
$Events = @();

if ($NumOfDCs -lt 1)
    {
        Write-Host "There was a problem while getting the Domain Controllers list.`nMake sure you are connected to a domain and try again." -ForegroundColor Yellow;
	break
    }

$DCs | foreach {
        Write-Host "Checking $_ ($i of $NumOfDCs Domain Controllers)..." -ForegroundColor Cyan -NoNewline;
        $i++;
        $Events += Get-WinEvent -ComputerName $_ -FilterHashtable @{LogName="Directory Service"; id="1644" } -ErrorAction SilentlyContinue;
	    if (!$?) {
            Write-Host " An Error Occured. Check port connectivity." -ForegroundColor Yellow
        }
        else
        {
            Write-Host " Successful query." -ForegroundColor Green
        }
    }

If ($Events -ne $null) {
	Write-Host "Found $(($Events |Measure-Object).count) LDAP event ID 1644 entries, generating report..." -ForegroundColor Green;
	
	$Events | ForEach-Object { 
		$_ | Add-Member -MemberType NoteProperty -Name DC -force -Value $_.MachineName
		$_ | Add-Member -MemberType NoteProperty -Name TimeGenerated	-force -Value $_.TimeCreated
		$_ | Add-Member -MemberType NoteProperty -Name ClientIP -force -Value $_.Properties[4].Value.Substring(0, $($_.Properties[4].Value.LastIndexOf(":")))
		$_ | Add-Member -MemberType NoteProperty -Name ClientPort -force -Value $_.Properties[4].Value.Substring($($_.Properties[4].Value.LastIndexOf(":")+1),$_.Properties[4].Value.Length - $_.Properties[4].Value.LastIndexOf(":")-1)
        $_ | Add-Member -MemberType NoteProperty -Name UserName -force -Value $_.Properties[16].Value
		$_ | Add-Member -MemberType NoteProperty -Name StartingNode -force -Value $_.Properties[0].Value
		$_ | Add-Member -MemberType NoteProperty -Name Filter -force -Value $_.Properties[1].Value
		$_ | Add-Member -MemberType NoteProperty -Name SearchScope -force -Value $_.Properties[5].Value
		$_ | Add-Member -MemberType NoteProperty -Name AttributeSelection -force -Value $_.Properties[6].Value
		$_ | Add-Member -MemberType NoteProperty -Name ServerControls -force -Value $_.Properties[7].Value
		$_ | Add-Member -MemberType NoteProperty -Name VisitedEntries -force -Value $_.Properties[2].Value
		$_ | Add-Member -MemberType NoteProperty -Name ReturnedEntries -force -Value $_.Properties[3].Value
		$_ | Add-Member -MemberType NoteProperty -Name UsedIndexes -force -Value $_.Properties[8].Value
		$_ | Add-Member -MemberType NoteProperty -Name PagesReferenced -Force -Value $_.Properties[9].Value
		$_ | Add-Member -MemberType NoteProperty -Name PagesReadFromDisk -force -Value $_.Properties[10].Value
		$_ | Add-Member -MemberType NoteProperty -Name PagesPreReadFromDisk -force -Value $_.Properties[11].Value
		$_ | Add-Member -MemberType NoteProperty -Name CleanPagesModified -force -Value $_.Properties[12].Value
		$_ | Add-Member -MemberType NoteProperty -Name DirtyPagesModified -force -Value $_.Properties[13].Value
		$_ | Add-Member -MemberType NoteProperty -Name SearchTimeMS -force -Value $_.Properties[14].Value
		$_ | Add-Member -MemberType NoteProperty -Name AttributesPreventingOptimization -force -Value $_.Properties[15].Value
	}
}
else {
	Write-Host "No relevant entries found (Event ID 1644).`nEnsure that 'Directory Service Access' is audited, and the proper Registry key is set on DCs." -ForegroundColor Yellow;
    break
}

# wrap up
# save entries to CSV
$FileName = "$(Get-Location)\LDAPQueryPerformanceEventsAnalysis_$(Get-Date -Format HHmmssddmmyyyy).csv";

$Events | select TimeGenerated,ClientIP,ClientPort,UserName,DC,StartingNode,Filter,SearchScope,AttributeSelection,VisitedEntries,ReturnedEntries,UsedIndexes,SearchTimeMS,PagesPreReadFromDisk,PagesReadFromDisk,PagesReferenced,CleanPagesModified,DirtyPagesModified,AttributesPreventingOptimization,ServerControls | 
    Export-Csv $FileName -NoTypeInformation;

Write-Host "Entries saved to $FileName." -ForegroundColor Cyan;

# display entries in a grid
$Events | select TimeGenerated,ClientIP,ClientPort,UserName,DC,StartingNode,Filter,SearchScope,AttributeSelection,VisitedEntries,ReturnedEntries,UsedIndexes,SearchTimeMS,PagesPreReadFromDisk,PagesReadFromDisk,PagesReferenced,CleanPagesModified,DirtyPagesModified,AttributesPreventingOptimization,ServerControls | 
    Out-GridView -Title "LDAP Query Performance Events Analysis <$(get-date)>"