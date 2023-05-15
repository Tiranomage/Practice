import win32evtlog
import win32evtlogutil
import win32security
import datetime
import argparse

# Параметры скрипта
parser = argparse.ArgumentParser()
parser.add_argument("computer", help="имя или IP адрес удаленного компьютера")
parser.add_argument("--sid", help="SID пользователя")
parser.add_argument("--start", help="дата начала поиска событий в формате ДД.ММ.ГГГГ")
parser.add_argument("--end", help="дата окончания поиска событий в формате ДД.ММ.ГГГГ")
args = parser.parse_args()

# Параметры журнала событий
logtype = 'Security'
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
server = args.computer

# Собираем данные из журнала событий
events = []
hand = win32evtlog.OpenEventLog(server, logtype)
total = win32evtlog.GetNumberOfEventLogRecords(hand)

while True:
    events_buffer = win32evtlog.ReadEventLog(hand, flags, 0)
    if not events_buffer:
        break
    for event in events_buffer:
        if event.EventID in (4688, 4689):
            event_dict = {}
            event_dict['time'] = datetime.datetime.fromtimestamp(event.TimeGenerated).strftime('%d.%m.%Y %H:%M:%S')
            event_dict['computer'] = server
            event_dict['event_id'] = event.EventID
            event_dict['action'] = "Запуск процесса" if event.EventID == 4688 else "Завершение процесса"
            event_dict['user_sid'] = win32security.GetSecurityInfo(
                event.srcname, win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION).GetSecurityDescriptorOwner().ToString()
            if args.sid and event_dict['user_sid'] != args.sid:
                continue
            event_dict['user_name'] = win32evtlogutil.SafeGetUserObject(hand, event, flags)
            if not event_dict['user_name']:
                continue
            if args.start:
                start_date = datetime.datetime.strptime(args.start, '%d.%m.%Y')
                if start_date > event_dict['time']:
                    continue
            if args.end:
                end_date = datetime.datetime.strptime(args.end, '%d.%m.%Y')
                if end_date < event_dict['time']:
                    continue
            events.append(event_dict)

# Формируем выходные данные и записываем в файл
output = []
for event in events:
    output.append(f"Компьютер: {event['computer']}\n"
                  f"Время события: {event['time']}\n"
                  f"Пользователь: {event['user_name']} ({event['user_sid']})\n"
                  f"Действие: {event['action']}\n")
with open('output.txt', 'w') as f:
    f.writelines(output)
