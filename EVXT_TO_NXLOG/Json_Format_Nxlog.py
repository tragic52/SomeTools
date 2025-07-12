import json

# 读取经powershell转换后的JOSN文件
with open("result.txt",encoding="utf-8",mode="r") as f:
    json_string = f.read()

# 将嵌套的字典转化为扁平数组
def flatten_dict(d, parent_key='', sep=''):
    items = []
    for k, v in d.items():
        new_key = f"{sep}{k}" if parent_key else k
        # 为贴合NXLOG解析规则，重命名字段名称
        if new_key == "RenderedMessage":new_key = "Message"
        if new_key == "SystemTime":new_key = "EventTime"
        if new_key == "LogonGuid":new_key = "ProviderGuid"
        if new_key == "SubjectLogonId":new_key = "TargetLogonId"
        if new_key == "Computer":new_key = "Hostname"
        if new_key == "ElevatedToken":new_key = "TokenElevationType"
        if new_key == "SubjectUserSid":new_key = "TargetUserSid"
        if new_key == "SystemTime":new_key = "EventTime"
        if new_key == "TargetUserSid":new_key = "SubjectUserSid"
        if new_key == "TargetUserSid":new_key = "SubjectUserSid"
        

        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

# 初始化列表以存储展平的 JSON 对象
flattened_events = []

# 遍历读取JSON内容
for line in json_string.strip().split('\n'):
    try:
        
        event = json.loads(line)
        
        # 将JSON数据由嵌合格式转化为扁平格式，便于解析
        flattened_event = flatten_dict(event)
        
        # 处理特定映射以匹配之前的 JSON 结构
        if 'System.Microsoft-Windows-Security-Auditing.Guid' in flattened_event:
            flattened_event['ProviderGuid'] = flattened_event.pop('System.Microsoft-Windows-Security-Auditing.Guid')
        if 'System.Microsoft-Windows-Security-Auditing.Name' in flattened_event:
            flattened_event['ProviderName'] = flattened_event.pop('System.Microsoft-Windows-Security-Auditing.Name')
        if 'System.TimeCreated.SystemTime' in flattened_event:
            flattened_event['SystemTime'] = flattened_event.pop('System.TimeCreated.SystemTime')
        if 'System.Execution.ProcessID' in flattened_event:
            flattened_event['ProcessID'] = flattened_event.pop('System.Execution.ProcessID')
        if 'System.Execution.ThreadID' in flattened_event:
            flattened_event['ThreadID'] = flattened_event.pop('System.Execution.ThreadID')
        if 'System.Security' in flattened_event and not flattened_event['System.Security']:
            flattened_event['Security'] = None
            del flattened_event['System.Security']
        if 'System.Correlation' in flattened_event and not flattened_event['System.Correlation']:
            flattened_event['ActivityID'] = ""
            flattened_event['RelatedActivityID'] = ""
            del flattened_event['System.Correlation']
        
        # 移除无效字段
        if 'xmlns' in flattened_event:
            del flattened_event['xmlns']
        
        # 将转换后的数据汇总保存
        flattened_events.append(flattened_event)

    except json.JSONDecodeError as e:
        print(f"Error parsing JSON line: {e}")
        continue

# 保存JSON文件对象
for i, event in enumerate(flattened_events, 1):
    with open('WindowsEvents.txt', mode='a+', encoding='utf-8') as f:
        f.write(f"{json.dumps(event,ensure_ascii=False)}\n")
print("文件解析成功：WindowsEvents.txt")