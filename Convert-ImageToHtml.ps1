function Convert-ImageToHtml
{
    <#
            .SYNOPSIS
            This function can be used to convert an image file into an HTML IMG tag with an image
            embedded in the SRC so that an external image file doesn't have to be referenced.
            .PARAMETER $ImageFile
            The image file path.
            .PARAMETER $MakeHtml
            An HTML file will be created using the same name as the image file.
            .EXAMPLE
            PS C:\> Convert-ImageToHtml -$ImageFile c:\temp\picture.png -Verbose
            .EXAMPLE
            PS C:\> Get-ChildItem *.png | select fullname | Convert-ImageToHtml -Verbose
            .EXAMPLE
            PS C:\> Get-ChildItem *.png | select fullname | Convert-ImageToHtml -Verbose -MakeHtml
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
    #>
 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'The image file path.')]
        [string]$ImageFile,

        [Parameter(Mandatory = $false,
        HelpMessage = 'An HTML file will be created using the same name as the image file.')]
        [switch]$MakeHtml 
    )
 

    Process {

        try {           

            # Process for common parameter names if pipeline is used
            if($PSCmdlet.MyInvocation.ExpectingInput){
                $CheckFullName = $_ | gm | where name -like "fullname"
                if($CheckFullName){
                    $ImageFile = $_.fullname
                }
            }

            # Verbose info
            Write-Verbose "Processing $ImageFile"

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
