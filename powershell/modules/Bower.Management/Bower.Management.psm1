# Loads private helpers first, then public functions. The manifest's explicit
# FunctionsToExport list is the export contract; Export-ModuleMember mirrors it.
$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue)
$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public) | Sort-Object -Property FullName) {
    . $file.FullName
}

Export-ModuleMember -Function @($public.BaseName)
