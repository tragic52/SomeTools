# 注：PS使用中文输出容易因为编码报错，因此使用英文输出内容
# 本脚本用于解析Windows原生日志，并且将其转化为NXLOG输出的格式，最终将其送入SOC平台进行分析
# 询问用户解析的日志路径
$evtxPath = Read-Host "Enter the full path to the .evtx file (e.g., C:\logs\Security.evtx)"
if (-not (Test-Path $evtxPath)) {
    Write-Host "File not found: $evtxPath" -ForegroundColor Red
    exit
}

# 询问用户最终输出文件名
$outputName = Read-Host "Enter output file name (extension:txt)"
$outputPath = Join-Path -Path (Split-Path $evtxPath -Parent) -ChildPath "$outputName"

Write-Host "Processing, please wait..."

# 将日志解析为JSON格式，每行1个事件对象
$stream = [System.IO.StreamWriter]::new($outputPath, $false, [System.Text.Encoding]::UTF8)

Get-WinEvent -Path $evtxPath | ForEach-Object {
    $evt = $_
    $xml = [xml]$evt.ToXml()
    $eventData = @{}

    foreach ($d in $xml.Event.EventData.Data) {
        $key = $d.Name
        $val = $d.'#text'
        if ($key) { $eventData[$key] = $val }
    }

    # NXLOG日志格式
    $obj = [PSCustomObject]@{
        EventTime     = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Hostname      = $xml.Event.System.Computer
        EventType     = $evt.LevelDisplayName
        SeverityValue = $xml.Event.System.Level
        Severity      = $evt.LevelDisplayName
        SourceName    = $xml.Event.System.Provider.Name
        EventID       = $evt.Id
        RecordNumber  = $xml.Event.System.EventRecordID
        Message       = $evt.Message
        Category      = $xml.Event.System.Task
        Opcode        = $xml.Event.System.Opcode
        Keywords      = $xml.Event.System.Keywords
        AccountName   = $eventData["TargetUserName"]
    }

    $stream.WriteLine(($obj | ConvertTo-Json -Compress))
}

$stream.Close()

Write-Host "Done! File saved as UTF-8: $outputPath" -ForegroundColor Green
