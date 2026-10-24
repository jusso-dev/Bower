function Test-BowerSecurityEvent {
    <#
    .SYNOPSIS
    Validates a security event against the Bower envelope schema (1.0.0).

    .DESCRIPTION
    Accepts an event from New-BowerSecurityEvent, a hashtable, a PSCustomObject or a JSON
    string, and checks required fields, case-sensitive property names, lengths,
    enumerations, timestamps and the 1 MiB collector size limit. Returns $true or $false;
    use -Detailed for the list of problems. Validation is local and sends nothing.

    .PARAMETER InputObject
    The event to validate.

    .PARAMETER Detailed
    Return an object with Valid, EventId and Errors instead of a Boolean.

    .EXAMPLE
    Get-Content ./event.json -Raw | Test-BowerSecurityEvent -Detailed

    Validates an event stored as JSON and lists any problems.

    .EXAMPLE
    @{ schemaVersion = '1.0.0'; eventId = 'e1' } | Test-BowerSecurityEvent

    Returns $false because required fields are missing.

    .OUTPUTS
    System.Boolean, or Bower.SecurityEventValidation with -Detailed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    [OutputType('Bower.SecurityEventValidation')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object] $InputObject,

        [switch] $Detailed
    )

    process {
        $errors = @()
        $eventId = $null
        try {
            $eventId = (ConvertTo-BowerEventJson -InputObject $InputObject).EventId
        }
        catch [System.ArgumentException] {
            $errors = @($_.Exception.Message)
        }

        if ($Detailed) {
            [pscustomobject]@{
                PSTypeName = 'Bower.SecurityEventValidation'
                Valid      = $errors.Count -eq 0
                EventId    = $eventId
                Errors     = $errors
            }
        }
        else {
            foreach ($message in $errors) {
                Write-Verbose $message
            }
            $errors.Count -eq 0
        }
    }
}
