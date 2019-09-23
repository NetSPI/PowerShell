Function Convert-CsvToPsDt
{
    <#
            .SYNOPSIS
            This function can be used to convert a CSV into PowerShell code 
            that creates a data table that mirrors the CSV structure and content.
            .PARAMETER $Infile
            The csv input file path.
            .PARAMETER $Outfile
            The output file path.
            .EXAMPLE
            PS C:\> Convert-CsvToPsDt -Infile c:\temp\serverinfo.csv -Outfile c:\temp\createmydatatable.ps1
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,
        HelpMessage = 'The csv input file path.')]
        [string]$Infile,
        [Parameter(Mandatory = $true,
        HelpMessage = 'The output file path.')]
        [string]$Outfile = ".\MyPsDataTable.ps1"
    )

    # Test file path
    if(Test-Path $Infile)
    {
        Write-Output "[+] $Infile is accessible."
    }else{
        write-Output "[-] $Infile is not accessible, aborting."
        break
    }

    # Import CSV
    Write-Output "[+] Importing csv file."
    $MyCsv = Import-Csv $Infile

    # Get list of columns
    Write-Output "[+] Paring columns."
    $MyCsvColumns = $MyCsv | Get-Member | Where-Object MemberType -like "NoteProperty" | Select-Object Name -ExpandProperty Name

    # Print data table creation
    Write-Output "[+] Writing data table object to $Outfile."    
    write-output '$MyTable = New-Object System.Data.DataTable' | Out-File c:\temp\MyDataTable.txt

    # Print columns creation
    Write-Output "[+] Writing data table columns to $Outfile."    
    $MyCsvColumns |
    ForEach-Object {

        write-Output "`$null = `$MyTable.Columns.Add(`"$_`")" | Out-File c:\temp\MyDataTable.txt -Append
    
    }

    # Print data rows
    Write-Output "[+] Writing data table rows to $Outfile." 
    $MyCsv |
    ForEach-Object {
    
        # Create a value contain row data
        $CurrentRow = $_
        $PrintRow = ""
        $MyCsvColumns | 
        ForEach-Object{
            $GetValue = $CurrentRow | Select-Object $_ -ExpandProperty $_ 
            if($PrintRow -eq ""){
                $PrintRow = "`"$GetValue`""
            }else{         
                $PrintRow = "$PrintRow,`"$GetValue`""
            }
        }

        # Print row addition
        write-Output "`$null = `$MyTable.Rows.Add($PrintRow)" | Out-File c:\temp\MyDataTable.txt -Append
    }

    Write-Output "[+] All done."
}
