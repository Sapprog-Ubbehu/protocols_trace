# protocols_trace

## Описание
Этот скрипт выполняет трассировку до указанного домена или IP-адреса, извлекает IP-адреса из маршрута и получает информацию об автономной системе (AS), стране и провайдере.

## Использование
Запустите скрипт командой:
```sh
python trace_as.py <домен_или_ip>
```
Пример:
```sh
python trace_as.py ya.ru
```

## Формат вывода
Скрипт отобразит таблицу с данными:
```
№  | IP             | AS       | Country         | Provider
------------------------------------------------------------
1  | 8.8.8.8        | 15169    | США           | Google LLC
2  | 192.168.1.1    | Private  | Local Network | N/A
...
```

## Примечания
- Работает на Windows (`tracert`) и Linux/macOS (`traceroute`).
- Использует API `http://ipwho.is/` для получения информации об IP.
- Частные (локальные) IP-адреса и IP из диапазона CG-NAT (`100.64.0.0/10`) отмечаются как "Частный" и "Локальная сеть".
