# 📦 Инструкция по установке и настройке проекта

## 1. Установка зависимостей

### 1.1 Основные требования

* Python **3.8+**
* `pip` — менеджер пакетов Python
* **Рекомендуется использовать виртуальное окружение**

### 1.2 Установка пакетов

```bash
pip install Flask Flask-SQLAlchemy pyjwt python-dotenv
```

**Описание пакетов:**

* `Flask` — микрофреймворк для веб-приложений
* `Flask-SQLAlchemy` — интеграция SQLAlchemy с Flask
* `pyjwt` — работа с JWT-токенами
* `python-dotenv` — загрузка конфигурации из `.env` файла

### 1.3 Создание виртуального окружения

```bash
# Linux / MacOS
python -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

---

## 2. Настройка конфигурации

### 2.1 Создание `.env` файла

```bash
cp .env.example .env
```

**Пример содержимого `.env`:**

```env
# Администратор
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure_password_123
ADMIN_IS_ADMIN=true

# Пользователь
STUDENT_USERNAME=student
STUDENT_PASSWORD=student_pass
STUDENT_IS_ADMIN=false

# Приложение
SECRET_KEY=your_very_secret_key_here
DATABASE_URI=sqlite:///users.db
```

### 2.2 Рекомендации по безопасности

* Используйте сложные пароли (**12+ символов**)
* Не используйте значения по умолчанию в продакшене

---

## 3. Запуск проекта

### 3.1 Стандартный запуск

```bash
python app.py
```

Сервер будет доступен по адресу:
👉 [`http://localhost:5000`](http://localhost:5000)

---

## 4. Первоначальная настройка

### 4.1 Инициализация базы данных

При первом запуске:

1. Создается файл `instance/users.db`
2. Добавляются пользователи из `.env`
3. Назначаются права доступа

### 4.2 Первый вход

Откройте [http://localhost:5000](http://localhost:5000) и используйте данные:

* **Администратор:**
  `ADMIN_USERNAME` / `ADMIN_PASSWORD`

* **Пользователь:**
  `STUDENT_USERNAME` / `STUDENT_PASSWORD`

---

## 5. Дополнительные настройки

### 5.1 Настройка базы данных

Для использования **PostgreSQL** или **MySQL**, измените в `.env`:

```env
DATABASE_URI=postgresql://user:password@localhost/dbname
```

### 5.2 Настройка логирования

В `app.py` добавьте:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log'
)
```

---

## 6. Решение проблем

### 6.1 Частые ошибки

| Ошибка                | Решение                                     |
| --------------------- | ------------------------------------------- |
| `Port already in use` | Измените порт или завершите занятый процесс |
| `Module not found`    | Убедитесь, что все зависимости установлены  |
| `DB connection error` | Проверьте строку подключения в `.env`       |

### 6.2 Сброс базы данных

1. Удалите файл `instance/users.db`
2. Перезапустите приложение

---

## 7. Обновление проекта

```bash
# Остановите сервер

# Обновите зависимости
pip install -U -r requirements.txt

# Запустите снова
python app.py
```

Гудков Никита ИСП-308
