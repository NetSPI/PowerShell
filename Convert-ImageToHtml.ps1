function Convert-ImageToHtml
{
    <#
            .SYNOPSIS
            This function can be used to convert an image file into an HTML IMG tag with an image
            embedded in the SRC so that an external image file doesn't have to be referenced.
            .PARAMETER $Infile
            The image file path.
            .PARAMETER $Outfile
            The html output file path.
            .EXAMPLE
            PS C:\> Convert-CsvToPsDt -Infile c:\temp\serverinfo.csv -Outfile c:\temp\createmydatatable.ps1
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
    #>
 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,
        HelpMessage = 'The image file path.')]
        [string]$ImageFile,

        [Parameter(Mandatory = $false,
        HelpMessage = 'The html output file path.')]
        [string]$HtmlFile = ".\image.html"
    )
 

    Process {

        try {
            # Read image file
            $ImageBytes  = [System.IO.File]::ReadAllBytes("$ImageFile")

            # Convert to base64 string
            $ImageString = [System.Convert]::ToBase64String($ImageBytes)

            # Create HTML with an embedded image
            $output = "<img src=`"data:image/png;base64, $ImageString`" />"

            # Display image tag
            $output

            if($HtmlFile){
            $output | Out-File "$HtmlFile"
            }
        }catch{
            Write-Error "Something went wrong. Check your paths. :)" -ErrorId B1 -TargetObject $_
        }

    }
}
