param([string]$OutputSuffix = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$html = Join-Path $root "VPUFT_Scenario5_Dataset_B_Method_B_Corrected_Final.html"
$docx = Join-Path $root ("VPUFT_Chapter5_MethodB_Corrected_Final_AR{0}.docx" -f $OutputSuffix)
$pdf = Join-Path $root ("VPUFT_Chapter5_MethodB_Corrected_Final_AR{0}.pdf" -f $OutputSuffix)
$word = $null
$doc = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $doc = $word.Documents.Open($html, $false, $false, $false)
    $doc.SaveAs2($docx, 16)
    $doc.ExportAsFixedFormat($pdf, 17)
    $doc.Close(0)
    $doc = $null
    Write-Output "EXPORTED DOCX and PDF"
}
finally {
    if ($doc -ne $null) { $doc.Close(0) }
    if ($word -ne $null) { $word.Quit() }
    if ($doc -ne $null) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($doc) }
    if ($word -ne $null) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word) }
}
