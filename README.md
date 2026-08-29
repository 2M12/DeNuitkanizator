<div align="center">
  
<p align="center">
  <img src="assets/logo.png" width="256" alt="DeNuitkanizator">
</p>

<br>
<h1>🔬 DeNuitkanizator</h1>
<h4>Утилита для анализа .exe‑файлов, собранных через Nuitka (а также PyInstaller и другие упаковщики) и других exe-файлов не на Python. Извлекает метаданные, строки, модули, информацию о PE‑структуре и другую полезную информацию.</h4>

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Nuitka](https://img.shields.io/badge/Nuitka-Analyzer-2D2D2D?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Version](https://img.shields.io/badge/version-1.5-blue)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/2M12/DeNuitkanizator?style=for-the-badge)
![GitHub stars](https://img.shields.io/github/stars/2M12/DeNuitkanizator?style=for-the-badge)
![GitHub watchers](https://img.shields.io/github/watchers/2M12/DeNuitkanizator?style=for-the-badge)
![GitHub repo size](https://img.shields.io/github/repo-size/2M12/DeNuitkanizator?style=for-the-badge)

<p align="center">
  <img src="assets/thumbnail.png" width="700" alt="DeNuitkanizator">
</p>

</div>

<br>

---
>[!WARNING] 
>
> ## 🇬🇧 Not for a Russian audience
> If you are an English audience, then read [README-en.md](https://github.com/2M12/DeNuitkanizator/blob/main/README-en.md)

## ❓ Зачем это нужно

**Nuitka** компилирует Python в машинный код. Ваш `.py` становится нативным `.exe`, и заглянуть внутрь стандартными средствами уже нельзя. PyInstaller ещё можно распаковать, а Nuitka — нет.

**DeNuitkanizator** решает эту проблему. Он:
- Показывает, чем собран файл
- Извлекает всё, что можно извлечь: строки, модули, пути, IP, URL
- Дизассемблирует машинный код полностью
- Находит связи между кодом и строками
- Обнаруживает подозрительные паттерны

**Для кого:** reverse-инженеры, malware-аналитики, разработчики на Python, исследователи безопасности.

> **Важно:** это не декомпилятор. Nuitka компилирует Python в C, а затем в машинный код - восстановить полностью исходный код практитечски **невозможно**.
---
> [!WARNING]
> ## Перед использованием программы обязательно ознакомьтесь с [EULA.md — лицензионное соглашение](https://github.com/2M12/DeNuitkanizator/blob/main/EULA.md)
---
> [!CAUTION]
> 
> ### ❗ О ложных копиях
> Официальные источники только те, которые есть в профиле [2M12](https://github.com/2M12/2M12/blob/main/README.md). Телеграм-каналы/группы и в других источниках я ничего не выкладываю (они не являются официальными). Если вы наткнулись на что-то вне этого репозитория - это ложные копии, которые часто содержат вредоносное ПО.

>[!NOTE] 
>
>### ❗ Важные замечания
>* Результаты анализа **не гарантированы** - зависят от версии Nuitka, настроек компиляции и использования LTO.
>* Инструмент предоставляется **"как есть"** (as is).
>* **Приоритетная цель — Nuitka**, но анализатор успешно работает и с PyInstaller, cx_Freeze и другими упаковщиками.
>* Программа умеет анализировать обычный exe-файл, который написан не на Python.
>* PyInstaller выдаёт более подробную информацию, так как устроен проще и хранит больше метаданных внутри .exe.
>* Программа умеет разбирать нативные exe-файлы и другие упаковщики.

## 🔍 Возможности

### 🕵️ Обнаружение
* Определяет сборку через **Nuitka** (по 8 сигнатурам и энтропии `.rsrc`).
* Отличает Nuitka от PyInstaller и cx_Freeze (пишет Unknown если другой упаковщик - пока что).
* Определяет версию **Python** (3.7–3.11) по magic‑числам.

### 📥 Извлечение данных
* **Строки**: ASCII (4+/8+ символов), UTF‑16LE, UTF‑8
* **Модули**: имена импортированных и замороженных (`frozen`) модулей Python.
* **Пути к исходникам**: отладочные пути из `.rdata`/`.data`.
* **Имена переменных и функций**: идентификаторы из секций данных.
* **Сетевые данные**: IP‑адреса, URL, email‑адреса.

### 🧩 Анализ PE‑структуры
* **Секции**: имена, размеры, энтропия, права доступа, флаг исполняемости (EXEC).
* **Импорты**: все DLL и функции (включая Python C API).
* **Экспорты**: экспортируемые функции.
* **Хэши**: MD5, SHA1, SHA256 файла.
* **Компилятор**: определение (MinGW GCC, MSVC, Clang/LLVM).
* **Механизмы защиты**: DEP, ASLR.

### 🗜️ Распаковка
* **Zstandard (zstd)**: основной алгоритм сжатия Nuitka OneFile.
* **Zlib**: поиск и распаковка альтернативных сжатых блоков.
* Поиск сжатых блоков по сигнатурам: zlib, gzip, lzma, bzip2, zip.

### 💻 Дизассемблирование (при наличии Capstone)
* **Полный дизассемблинг** всех исполняемых секций (`Disasm/full/`).
* **Точка входа (Entry Point)**: с комментариями `[CALL]`, `[JMP]`, `[RET]`, `[ANTI-DEBUG]`.
* **Автоопределение архитектуры**: x86 или x64 по PE‑заголовку.
* **Кросс‑ссылки на строки** (`string_xrefs.txt`): какой код ссылается на какие строки.
* **Перевод по технологии Asm-to-C**: теперь .text_full.asm полностью переводится в читаемый C-код. Вдохновился инструментом построчного перевода [cisol](https://github.com/rdbv/cisol)
* **Основа технологии Asm-to-C**: Эмулируются регистры, стек (`push`/`pop`), флаги (`ZF`, `CF`, `OF`, `SF`, `PF`, `AF`). Также вызовы функций эмулируются через `goto`-метки.

>[!NOTE]
> ### 🔄 Asm-To-C
> **Asm-To-C** технология перевода ассемблерного кода (x86/x64) в читаемый C-код. Основана на построчном преобразовании инструкций: каждая ассемблерная инструкция транслируется в эквивалентный C-макрос, эмулирующий работу регистров, стека, флагов (ZF, CF, OF, SF, PF, AF) и памяти.
>
>Вызовы функций эмулируются через goto-метки, push/pop - через стековые макросы. Технология вдохновлена проектом [cisol](https://github.com/rdbv/cisol) и адаптирована для интеграции в DeNuitkanizator.
>**Формат вывода:** читаемый C-код с комментариями, в которых сохранены оригинальные ассемблерные инструкции. Предназначен для анализа и понимания логики бинарного кода, а не для компиляции.
><p align="center">
>  <img src="assets/AsmToC.jpg" width="256" alt="Asm-to-C Technology">
></p>

### ⚠️ Поиск подозрительных элементов
* **Anti‑debug API**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` и др.
* **Anti‑debug паттерны в коде**: `rdtsc`, `int 3`, `mov eax, fs:[30h]`.
* **Packed sections**: аномальное соотношение raw/virtual размеров.
* **High entropy**: секции с высокой энтропией (возможное шифрование).

### 🔄 Автообновление
* Проверка новых версий через GitHub API при запуске.
* Индикатор статуса: Latest / Update Available / Offline.

## 🖼️ Скриншоты

<p align="center">
  <img src="assets/main_menu.png" width="700" alt="Главное меню">
  <br><em>Главное меню — ввод пути к .exe</em>
</p>

<p align="center">
  <img src="assets/analysis_process.png" width="700" alt="Процесс анализа">
  <br><em>Процесс анализа в реальном времени</em>
</p>

<p align="center">
  <img src="assets/summary.png" width="700" alt="Итоговый отчёт">
  <br><em>Итоговый отчёт summary.txt</em>
</p>

---

>[!WARNING]
>
>### ⚠️ Ограничения
>
>* **Не восстанавливает исходный Python‑код.**
>* **Не декомпилирует машинный код обратно в Python.**
>* **Не гарантирует 100 % извлечение всех данных.**
>* Может пропустить часть информации при агрессивной **LTO‑оптимизации**.

---

## 📥 Установка

### Способ 1: Готовый .exe
Скачай `DeNuitkanizator.exe` из [Releases](https://github.com/2M12/DeNuitkanizator/releases) и запусти.

### Способ 2: Из исходников
```bash
git clone https://github.com/2M12/DeNuitkanizator.git
cd DeNuitkanizator
pip install -r requirements.txt
python DeNuitkanizator.py
```
---
## 🛠 Инструкция
1. Зайдите в программу `DeNuitkanizator.exe` или если вы скачали python-файл, то `DeNuitkanizator.py`.
2. Далее введите путь .exe файла или просто напишите сразу `python DeNuitkanizator.py "путь"`.
3. Затем начнётся анализ файла и появится результат в папке DeNuitkanizator_Output.
4. Вы можете дальше сами рассматривать файлы. В summary.txt лежит только сводка.

## Пример работы
<p align="center">
  <img src="example.gif" width="900" alt="DeNuitkanizator Example">
</p>

---
## 🔵 Требования
### Права администратора
### Если скачивается .py скрипт - установка нужных библиотек

## ☑️ Hash-суммы
```bash
MD5	95dd9a29ae0bd7ff4f9421bf7b1039bb
SHA-256	0a446375c9951fc14f5b19eb90ae0891d380dee2d494c43afaf0ec215a2dda6b
```
## 📜 Лицензия
MIT © 2026 Mikhail (2M12) / ThreatBit
