![Supported Python versions](https://img.shields.io/badge/python-3.8+-blue.svg)
![Supported Python versions](https://img.shields.io/badge/python-3.13+-blue.svg)
![Vue3](https://img.shields.io/badge/vue-3+-3eaf7c.svg?style=flat-square&logo=vue.js)
![Vue3 UI](https://img.shields.io/badge/vue3-UI-ff69b4.svg?style=flat-square&logo=vue.js)
![MIT](https://img.shields.io/badge/license-MIT-ccc.svg?style=flat-square&logo=reliance-industries-limited)

<p align="center">
        <img alt="Static" src="https://github.com/sh94ya/MetaView/blob/main/workspace/view/icons/favicon/favicon-128x128.png?raw=true">
</p>

## 🚀 MetaView — Metasploit Framework Web Ui on Vue3 for Penetration Testing

    Веб-интерфейс для Metasploit Framework с поддержкой многопользовательской работы и интуитивным UI

## ✨ Возможности
🖥 Современный веб-интерфейс

    Визуализация данных, хранящихся в БД Metasploit Framework

    Импортирование данных из MaxPatrol, Nmap, Acunetix

    Просмотр структуры тестируемых веб-сайтов

## 👥 Многопользовательский режим

    Несколько специалистов одновременно

    Разделение ролей и проектов

    История операций с тегами

    Создание задач для пользователей проекта

## 📊 Мониторинг и аналитика

    Live-дашборды с метриками

    Визуализация результатов сканирования

## 🚀 Быстрый старт
Локальная установка (требуется **Python 3.8 - 3.13**)
```bash
# Клонируем репозиторий
git clone https://github.com/sh94ya/MetaView.git
cd MetaView

pip install -r requirements.txt
python main.py

# Открываем в браузере (стандартный пароль admin:admin)
http://localhost:5000
```

## 🔧 Конфигурация

Отредактируйте config.ini файл:

### Metasploit DB настройки
Подключитесь к БД Metasploit Framework
```
login=msf
password=msf
address=127.0.0.1
port=5432
db=msf
```

### Безопасность
Смените свой секретный ключ:
```
secret_key = 'change-your-secret_key'
```


## 🛠 Технологический стек
Backend

    Flask — веб-сервер

    PostgreSQL — хранение данных и сессий

Frontend

    Vue 3 + Composition API — реактивный интерфейс

    Vuex — состояние приложения


## ⚠️ Ответственность

ВАЖНО: Данный инструмент предназначен исключительно для:

    Легального пентестинга

    Образовательных целей

    Исследований в области кибербезопасности

Разработчик не несет ответственности за незаконное использование.


## 📄 Лицензия

Распространяется под лицензией MIT. См. файл LICENSE для деталей.

## 👨‍💻 Автор

    sh94ya — Lead Developer — GitHub

## 🌟 Поддержка проекта

Поставьте ⭐️ на GitHub, если проект вам понравился!
