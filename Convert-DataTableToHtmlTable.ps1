function Convert-DataTableToHtmlTable
{
    <#
            .SYNOPSIS
            This function can be used to convert a data table or ps object into a html table.
            .PARAMETER $DataTable
            The datatable to input.
            .PARAMETER $Outfile
            The output file path.
            .PARAMETER $Title
            Title of the page.
            .PARAMETER $Description
            Description of the page.
            .EXAMPLE
            $object = New-Object psobject
            $Object | Add-Member Noteproperty Name "my name 1"
            $Object | Add-Member Noteproperty Description "my description 1"
            Convert-DataTableToHtmlTable -Verbose -DataTable $object -Outfile ".\MyPsDataTable.html" -Title "MyPage" -Description "My description" -DontExport
            Convert-DataTableToHtmlTable -Verbose -DataTable $object -Outfile ".\MyPsDataTable.html" -Title "MyPage" -Description "My description"            
            .\MyPsDataTable.html
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
    #>
    param (
        [Parameter(Mandatory = $true,
        HelpMessage = 'The datatable to input.')]
        $DataTable,
        [Parameter(Mandatory = $false,
        HelpMessage = 'The output file path.')]
        [string]$Outfile = ".\MyPsDataTable.html",
        [Parameter(Mandatory = $false,
        HelpMessage = 'Title of page.')]
        [string]$Title = "HTML Table",
        [Parameter(Mandatory = $false,
        HelpMessage = 'Description of page.')]
        [string]$Description = "HTML Table",
        [Parameter(Mandatory = $false,
        HelpMessage = 'Disable file save.')]
        [switch]$DontExport
    )

    # Setup HTML begin
    Write-Verbose "[+] Creating html top." 
    $HTMLSTART = @"
    <html>
        <head>
          <title>$Title</title>
          <style> 	
  
	        {box-sizing:border-box}
	        body,html{
		        font-family:"Open Sans", 
		        sans-serif;font-weight:400;
		        min-height:100%;;color:#3d3935;
		        margin:1px;line-height:1.5;
		        overflow-x:hidden
	        }
		
	        table{
		        width:100%;
		        max-width:100%;
		        margin-bottom:1rem;
		        border-collapse:collapse
	        }
	
	        table thead th{
		        vertical-align:bottom;
		        border-bottom:2px solid #eceeef
	        }
	
	        table tbody tr:nth-of-type(odd){
		        background-color:#f9f9f9
	        }
	
	        table tbody tr:hover{
		        background-color:#f5f5f5
	        }
	
	        table td,table th{
		        padding:.75rem;
		        line-height:1.5;
		        text-align:left;
		        font-size:1rem;
		        vertical-align:top;
		        border-top:1px solid #eceeef
	        }

	
	        h1,h2,h3,h4,h5,h6{
		        padding-left: 10px;
		        font-family:inherit;
		        font-weight:500;
		        line-height:1.1;
		        color:inherit
	        }
	
	        code{
		        padding:.2rem .4rem;
		        font-size:1rem;
		        color:#bd4147;
		        background-color:#f7f7f9;
		        border-radius:.25rem
	        }
	
	        p{
		        margin-top:0;
		        margin-bottom:1rem
	        }
	
	        a,a:visited{
		        text-decoration:none;
		        font-size: 14;
		        color: gray;
		        font-weight: bold;
	        }
	
	        a:hover{
		        color:#9B3722;
		        text-decoration:underline
	        }
		
	        .link:hover{
		        text-decoration:underline
	        }
	
	        li{
		        list-style-type:none
	        }	

            .pageDescription {
                margin: 10px;
            }
  
	        .divbarDomain{
		        background:#d9d7d7;
		        width:200px;
		        border: 1px solid #999999;
		        height: 25px;
		        text-align:center;
	        }
  
	        .divbarDomainInside{
		        background:#9B3722;
		        width:100px;
		        text-align:center;
		        height: 25px;
		        vertical-align:middle;
            }
            .pageDescription {
                padding-left: 0px;
            }				
          </style>
        </head>
        <body>
        <p class="pageDescription"><a href="javascript:history.back()">Back to Report</a></p>
        <p class="pageDescription"><h3>$Title</h3></p>
        <p class="pageDescription">$Description</p>
            <table class="table table-striped table-hover">
"@
    
    # Get list of columns
    Write-Verbose "[+] Parsing data table columns."
    $MyCsvColumns = $DataTable | Get-Member | Where-Object MemberType -like "NoteProperty" | Select-Object Name -ExpandProperty Name

    # Print columns creation
    Write-Verbose "[+] Creating html table columns."   
    $HTMLTableHeadStart= "<thead><tr>" 
    $MyCsvColumns |
    ForEach-Object {

        # Add column
        $HTMLTableColumn = "<th>$_</th>$HTMLTableColumn"    
    }
    $HTMLTableColumn = "$HTMLTableHeadStart$HTMLTableColumn</tr></thead>" 

     # Create table rows
    Write-Verbose "[+] Creating html table rows."     
    $HTMLTableRow = $DataTable |
    ForEach-Object {
    
        # Create a value contain row data
        $CurrentRow = $_
        $PrintRow = ""
        $MyCsvColumns | 
        ForEach-Object{
            $GetValue = $CurrentRow | Select-Object $_ -ExpandProperty $_ 
            if($PrintRow -eq ""){
                $PrintRow = "<td>$GetValue</td>"               
            }else{         
                $PrintRow = "<td>$GetValue</td>$PrintRow"
            }
        }
        
        # Return row
        $HTMLTableHeadstart = "<tr>" 
        $HTMLTableHeadend = "</tr>" 
        "$HTMLTableHeadStart$PrintRow$HTMLTableHeadend"
    }

    # Setup HTML end
    Write-Verbose "[+] Creating html bottom." 
    $HTMLEND = @"
  </tbody>
</table>
</body>
</html>
"@

    # Return it
    "$HTMLSTART $HTMLTableColumn $HTMLTableRow $HTMLEND" 

    # Write file
    if(-not $DontExport){
        "$HTMLSTART $HTMLTableColumn $HTMLTableRow $HTMLEND"  | Out-File $Outfile
    }
}
