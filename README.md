# Проект BlackICE Search

Поисковик, основанный на `nmap`

## Как запустить

1. Python WEB интерфейс: 
    
    ```shell
    cd ./code/python
    python -m venv venv
    pip install flask requests beautifulsoup4
    python ./webview.py
    ```

2. Сканер сети (новых IP адресов)

    В коде (`./code/tests/main.cpp`) измените IP сервера

    ```cpp
    ...
    req.url = "http://192.168.31.100:8080/new_ip";
    ...
    ```

    На IP, где у вас запущен веб интерфейс


    ```shell
    sudo ./tools/cmp --file=main.cpp --only-run=true!
    ```

    `sudo` для того, чтобы работал SYN скан
    `true!` означает, что проект сначала скомпилируется, потом запустится, а не просто запустит существующую версию