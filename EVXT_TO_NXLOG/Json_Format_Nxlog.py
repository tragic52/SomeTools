import json

# Input JSON string (simulating reading from demo.txt)
with open("1-json.txt", encoding="utf-8", mode="r") as f:
    json_string = f.read()

# 将嵌套的字典转化为扁平数组
def flatten_dict(d, parent_key='', sep=''):
    items = []
    for k, v in d.items():
        new_key = f"{sep}{k}" if parent_key else k
        # 为贴合NXLOG解析规则，重命名字段名称
        if new_key == "RenderedMessage":
            new_key = "Message"
        if new_key == "SystemTime":
            new_key = "EventTime"
        if new_key == "LogonGuid":
            new_key = "ProviderGuid"
        if new_key == "SubjectLogonId":
            new_key = "TargetLogonId"
        if new_key == "Computer":
            new_key = "Hostname"
        if new_key == "ElevatedToken":
            new_key = "TokenElevationType"
        if new_key == "SubjectUserSid":
            new_key = "TargetUserSid"
        if new_key == "SystemTime":
            new_key = "EventTime"
        if new_key == "TargetUserSid":
            new_key = "SubjectUserSid"

        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

# 初始化列表以存储展平的 JSON 对象
flattened_events = []

# 将每一行都作为 JSON 对象进行读取和处理
for line in json_string.strip().split('\n'):
    try:
        # 解析JSON行
        event = json.loads(line)

        # 将 JSON 对象扁平化
        flattened_event = flatten_dict(event)

        # 处理特定的映射以匹配先前的 JSON 结构
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

        # 移除xmlns无效字段
        if 'xmlns' in flattened_event:
            del flattened_event['xmlns']

        # Add to list of flattened events
        flattened_events.append(flattened_event)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON line: {e}")
        continue

# 保存JSON文件对象
for i, event in enumerate(flattened_events, 1):
    with open('WindowsEvents.txt', mode='a+', encoding='utf-8') as f:
        # 使用 separators=(',', ':') 去除键值对之间的空格
        f.write(f"{json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n")
