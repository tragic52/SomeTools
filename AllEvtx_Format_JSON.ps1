# 本程序用于将Windows原生日志全部解析转化为每行1条JSON格式数据的TXT日志
# Path变量不要用中文路径
# 或者使用命令行执行脚本：.\AllEvtx_Format_JSON.ps1 -PATH "C:\Users\Adil\Desktop\Security.evtx" -Output "result.txt"
param (
    [string]$Path = "C:\Users\Security.evtx",
    [string]$Output = "result.txt"
)

# 遍历解析数据
function Convert-XmlNodeToHashtable {
    param ($node)

    $result = @{}

    # 属性处理
    if ($node.Attributes) {
        foreach ($attr in $node.Attributes) {
            $result[$attr.Name] = $attr.Value
        }
    }

    # 子节点处理
    foreach ($child in $node.ChildNodes) {
        if ($child.NodeType -eq "Element") {
            if ($child.HasChildNodes -and $child.ChildNodes.Count -eq 1 -and $child.FirstChild.NodeType -eq "Text") {
                $result[$child.Name] = $child.InnerText
            } else {
                $result[$child.Name] = Convert-XmlNodeToHashtable $child
            }
        }
    }

    return $result
}

# 设置输出编码为 UTF-8（含 BOM，适配中文）
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $false

# 检查 evtx 文件是否存在
if (-not (Test-Path $Path)) {
    Write-Error "file not exist：$Path"
    exit
}

# 读取日志事件
$events = Get-WinEvent -Path $Path

# 准备输出文件（清空旧内容）
[System.IO.File]::WriteAllText($Output, "", $Utf8NoBomEncoding)

foreach ($eventitem in $events) {
    $xml = [xml]$eventitem.ToXml()
    $eventObj = Convert-XmlNodeToHashtable $xml.DocumentElement
    $eventObj["RenderedMessage"] = $eventitem.Message

    # 转换为一行 JSON（无换行压缩格式）
    $jsonLine = $eventObj | ConvertTo-Json -Depth 10 -Compress

    # 追加写入文件（UTF-8 编码）
    [System.IO.File]::AppendAllText($Output, $jsonLine + "`n", $Utf8NoBomEncoding)
}

Write-Host " Successfully exported $($events.Count) logs as UTF-8 formatted JSON Lines: $Output"