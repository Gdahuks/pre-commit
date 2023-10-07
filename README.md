# Narzędzia do statycznej analizy kodu

## Wstęp

### Czym są narzędzia do statycznej analizy kodu?

Narzędzia do statycznej analizy kodu to programy, które analizują kod źródłowy bez jego uruchamiania, w przeciwieństwie do analizy w czasie wykonania (runtime). Takie narzędzia służą między innymi do:

1. Wykrywania luk w zabezpieczeniach (`bandit`).
2. Wykrywania błędów w kodzie (`pylint`).
3. Sprawdzania zgodności z konwencją PEP8 (`flake8`).
4. Formatowania kodu (`black`).
5. Sprawdzania poprawności typów (`mypy`).
6. Sprawdzania dokumentacji (`pydocstyle`) oraz wielu innych zastosowań.

### Dlaczego warto używać narzędzi do statycznej analizy kodu?

Poza oczywistymi powodami, takimi jak wykrywanie błędów czy luk w kodzie, narzędzia te pozwalają utrzymać jeden standard kodu w całym projekcie, niezależnie od tego, ile osób nad nim pracuje.

### Jak i kiedy je uruchamiać?

Narzędzia te można uruchomić na kilka sposobów:
1. Pojedynczo, ręcznie, z linii poleceń, na przykład: `bandit -r .`. Narzędzie to rekurencyjnie przeszukuje katalog roboczy i wyświetla wyniki po zakończeniu. To rozwiązanie jest całkiem akceptowalne, gdy korzystamy z jednego narzędzia, ale gdy mamy ich kilka, może być uciążliwe uruchamianie każdego z nich.
2. Zbiorowo, podczas jakiejś akcji, wykorzystując na przykład narzędzie `pre-commit`. Wtedy narzędzia, które zdefiniujemy, uruchamiają się automatycznie, gdy wykonujemy jakąś akcję, na przykład `git commit`. To rozwiązanie jest lepsze, gdy korzystamy z wielu narzędzi, ale wymaga trochę więcej konfiguracji. Minusem tego rozwiązania jest to, że nie mamy pewności, czy inni członkowie zespołu nie wyłączyli sobie tych narzędzi, więc nie mamy pewności, że kod, który dostajemy od nich, jest sprawdzony.
3. Zdefiniowanie akcji w pipeline. Pipeline jest to automatyczny proces, w którym definiujemy, co ma się wydarzyć podczas wykonania jakiejś akcji np. próby zmergowania brancha roboczego z głównym branchem (definiuje się to między innymi w GitHub czy GitLab). Wtedy, gdy ktoś próbuje zmergować brancha, pipeline uruchamia się automatycznie i wykonuje wszystkie zdefiniowane w nim akcje (można zablokować wykonanie akcji, jeżeli pipeline się nie powiedzie). To rozwiązanie jest najlepsze, gdy korzystamy z wielu narzędzi i chcemy mieć pewność, że kod, który dostajemy od innych członków zespołu, jest sprawdzony. Minusem tego rozwiązania jest to, że wymaga najwięcej konfiguracji.

## Opis narzędzi

Poniżej znajduje się opis narzędzi, z których sam korzystam i będziemy omawiać w tej prezentacji.

### `bandit` - bezpieczny kod

Bandit to narzędzie zaprojektowane do znajdowania typowych błędów bezpieczeństwa w kodzie Pythona. W tym celu Bandit przetwarza każdy plik, buduje z niego AST (Abstract Syntax Trees) i uruchamia odpowiednie wtyczki względem węzłów AST. Po zakończeniu skanowania wszystkich plików bandit generuje raport.

Warto zaznaczyć, że bandit nie jest w stanie wykryć wszystkich potencjalnych zagrożeń w kodzie, ale może znacząco pomóc w identyfikacji wielu typowych błędów związanych z bezpieczeństwem. Programiści mogą również dostosować konfigurację bandit lub definiować własne reguły, aby uwzględniać specyficzne zagrożenia związane z ich projektem.

Raport składa się z dwóch metryk: `severity` oraz `confidence`. Severity określa powagę znalezionego problemu, a confidence określa pewność, z jaką bandit jest w stanie stwierdzić, że znaleziony problem jest rzeczywistym problemem. Każda z tych metryk ma cztery poziomy: `UNDEFINED`, `LOW`, `MEDIUM` oraz `HIGH`.

Jeżeli chcemy zignorować jakiś problem, możemy użyć komentarza `# nosec` w linii, w której występuje problem. Wtedy bandit zignoruje ten problem.

### `pylint` - jakość kodu

Pylint sprawdza błędy, wymusza standard kodowania, szuka niedociągnięć kodu i może sugerować, w jaki sposób kod może zostać zrefaktoryzowany.

Wiele środowisk programistycznych (IDE; np. Visual Studio Code, PyCharm) ma wbudowaną integrację z Pylint, co pozwala na automatyczną analizę kodu podczas jego edycji.

Pylint generuje na zakończenie analizy raport, w którym ocenia jakość kodu w skali od 0 do 10, gdzie wyższa ocena oznacza lepszą jakość. Pylint dokonuje tej oceny, analizując kod pod kątem wielu aspektów, takich jak:
- Zgodność z konwencją PEP8.
- Jakość samego kodu, włączając zrozumiałość i spójność.
- Zgodność z zasadami programowania obiektowego lub funkcyjnego.
- Zgodność z zasadami programowania asynchronicznego.
- Inne istotne kryteria i standardy zdefiniowane w konfiguracji.

Ten proces oceny pozwala programistom na śledzenie i utrzymanie wysokich standardów kodowania w swoich projektach, a także na identyfikowanie potencjalnych obszarów do poprawy.

Jednak co ważne, zdarza się, że standardy ustalone w pylint są po prostu dziwne i lepiej je zignorować. Jako przykład podam `R0902` tj.

> Used when class has too many instance attributes, try to reduce this to get a simpler (and so easier to use) class.

Wtedy możemy użyć komentarza `# pylint: disable=R0902` w linii, w której występuje problem. Wtedy pylint zignoruje ten problem.

Polecam w pliku `pyproject.toml` zmodyfikować długość linii kodu:
```toml
[tool.pylint]
max-line-length = 120
```

### `flake8` - zgodność z PEP8

Flake8 skupia się głównie na zgodności z konwencją PEP8, która jest oficjalnym stylem kodowania Pythona. PEP8 zawiera zalecenia dotyczące formatowania kodu, nazewnictwa, wcięć i innych aspektów estetycznych kodu źródłowego.

Korzystając z narzędzia Flake8, programiści mogą automatycznie sprawdzać, czy ich kod jest zgodny z tymi wytycznymi, co pomaga utrzymać spójny i czytelny styl kodu w projekcie. Flake8 analizuje pliki źródłowe, 

Przykładowe zalecenia PEP8, które Flake8 może sprawdzać, to:
- Długość linii kodu.
- Użycie spacji lub tabulatorów do wcięć.
- Umieszczanie pustego wiersza na końcu plików.
- Zbyt długie linie kodu.
- Stosowanie spacji przed i po operatorach.
- Zbyt wiele pustych wierszy między funkcjami lub klasami.
- Formatowanie komentarzy i docstringów.

Programiści mogą dostosowywać konfigurację Flake8, aby dostosować zalecenia do swoich preferencji lub wymagań projektu. Podobnie jak w przypadku innych narzędzi, można również używać komentarzy, takich jak `# noqa`, aby wyłączyć określone ostrzeżenia lub błędy, jeśli są one niepotrzebne lub niecelowe w danym kontekście.

Warto zmodyfikować maksymalną długość linii podczas uruchamiania dodać flagę:

```bash
--max-line-length=120
````

### `black` - formatowanie kodu

Black to narzędzie do formatowania kodu źródłowego Pythona. Jego głównym celem jest automatyczne formatowanie kodu zgodnie z określonymi konwencjami, co eliminuje spory związane z formatowaniem i stylami kodu w zespole programistycznym.

Narzędzie Black jest znane z tego, że jest bardzo rygorystyczne i nie pozostawia programiście zbyt dużego pola manewru w kwestii formatowania. Jego zasady są ściśle określone, co oznacza, że kod jest formatowany w sposób spójny i jednolity, co ułatwia czytanie i zrozumienie kodu.

Polecam w pliku `pyproject.toml` zmodyfikować długość linii kodu:
```toml
[tool.black]
line-length = 120
```

Co ważne `black` poza samym raportem, automatycznie formatuje kod, więc nie musimy tego robić ręcznie.

### `mypy` - sprawdzanie typów

Python jest językiem dynamicznie typowanym, co oznacza, że zmienne i argumenty funkcji nie mają z góry określonych typów. Jednak Mypy pozwala programistom wymusić adnotacje typów do swojego kodu (aby utrzymać standard) i sprawdza, czy typy te są zgodne z rzeczywistym zachowaniem kodu.

Moja konfiguracja mypy (plik pyproject.toml):
```toml
[tool.mypy]
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = false
ignore_missing_imports = true
disable_error_code = ["import"]
```

Mypy bywa czasem problematyczne, przy nieodpowiedniej konfiguracji będzie się czepiał kodu bibliotek, które importujemy i nie mamy wpływu na to, że nie zaimplementowano tam typowania.


## Podstawy pracy z narzędziami do statycznej analizy kodu

W tym punkcie skupimy się na narzędziu `bandit`, jednak praca z pozostałymi narzędziami będzie analogiczna.

### Środowisko

Raczej nie chcemy zaśmiecać naszego środowiska głównego narzędziami do statycznej analizy kodu, więc utworzymy sobie środowisko wirtualne, w którym będziemy je uruchamiać. 

```bash
conda create -n pre-commit python=3.11
```

Następnie aktywujemy je:

```bash
conda activate pre-commit
```

### Instalacja narzędzi

Większość narzędzi możemy zainstalować za pomocą `pip`. 

```bash
conda activate pre-commit
pip install bandit
```

### Uruchomienie narzędzi

Większość narzędzi uruchamiamy z linii poleceń, podając jako argument ścieżkę do katalogu, który chcemy przeszukać.

```bash
conda activate pre-commit
bandit -r .
```

Chcemy przeszukać katalog roboczy (`.`), a opcja `-r` oznacza, że chcemy przeszukać go rekurencyjnie.

### Przetestowanie narzędzia

Stwórzmy w naszym projekcie plik `bandit.py`. Zostawmy go pusty. Uruchommy `bandit` na tym pliku.

Powinniśmy otrzymać coś w tym stylu:
```bash
❯ bandit -r .
[main]  INFO    profile exclude tests: None
[main]  INFO    cli include tests: None
[main]  INFO    cli exclude tests: None
[main]  INFO    running on Python 3.9.18
Run started:2023-10-03 10:58:19.012074

Test results:
        No issues identified.

Code scanned:
        Total lines of code: 0
        Total lines skipped (#nosec): 0

Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low: 0
                Medium: 0
                High: 0
        Total issues (by confidence):
                Undefined: 0
                Low: 0
                Medium: 0
                High: 0
Files skipped (0):
```

Dodajmy teraz kod do tego pliku:
```python
import os

def insecure_function(user_input):
    os.system(f"rm -rf {user_input}")

user_input = input("Podaj ścieżkę do pliku: ")
insecure_function(user_input)
```

Teraz po uruchomieniu `bandit` powinniśmy otrzymać informacje o `Issue`:
```bash
❯ bandit -r .
[main]  INFO    profile exclude tests: None
[main]  INFO    cli include tests: None
[main]  INFO    cli exclude tests: None
[main]  INFO    running on Python 3.9.18
Run started:2023-10-03 11:00:51.174825

Test results:
>> Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection detected, security issue.
   Severity: High   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b605_start_process_with_a_shell.html
   Location: ./bandit.py:4:4
3       def insecure_function(user_input):
4           os.system(f"rm -rf {user_input}")
5       

--------------------------------------------------

Code scanned:
        Total lines of code: 5
        Total lines skipped (#nosec): 0

Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low: 0
                Medium: 0
                High: 1
        Total issues (by confidence):
                Undefined: 0
                Low: 0
                Medium: 0
                High: 1
Files skipped (0):
```

W ten sposób dzięki statycznej analizie kodu wykryliśmy potencjalną lukę w zabezpieczeniach naszego kodu.

## Korzystanie z `pre-commit`

### Co to jest `pre-commit`?

Pre-commit to narzędzie, które pomaga programistom w automatyzacji procesu statycznej analizy kodu i różnych operacji na kodzie źródłowym przed zacommitowaniem go do repozytorium. W pliku `.pre-commit-config.yaml` definiujemy, jakie narzędzia mają się uruchomić i w jakiej kolejności przy próbie wykonania commita. Jeżeli wszystkie narzędzia zwrócą kod 0, to commit się wykona, jeżeli nie, to commit się nie wykona.

Podobnym narzędziem jest `pre-push`, które uruchamia się przed próbą pushowania zmian do repozytorium. Narzędzia te działają dzięki współpracy z hookami gitowymi. Hook to skrypt, który uruchamia się w konkretnym momencie (np. przed wykonaniem commita/pusha). Możemy je znaleźć w folderze `.git/hooks`.

### Instalacja

```bash
conda activate pre-commit
pip install pre-commit
```

### Konfiguracja

Należy utworzyć plik `.pre-commit-config.yaml` w głównym katalogu projektu. W nim definiujemy, jakie narzędzia mają się uruchomić i w jakiej kolejności. Przykładowa konfiguracja:
```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.7.0
    hooks:
      - id: black

  - repo: https://github.com/pylint-dev/pylint
    rev: v2.17.5
    hooks:
      - id: pylint

  - repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
      - id: flake8
        args:
          - "--max-line-length=120"

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.5.1
    hooks:
      - id: mypy
        name: mypy (first_package)
        pass_filenames: false
        args:
          - "first_package/"

      - id: mypy
        name: mypy (second_package)
        pass_filenames: false
        args:
          - "second_package/"

  - repo: https://github.com/PyCQA/bandit
    rev: '1.7.5'
    hooks:
      - id: bandit
        args:
          - "-r"
          - "."
```

Podajemy więc link do repozytorium, numer wersji, z jakiej chcemy skorzystać, a następnie definiujemy konkretne hooki. Dla przykładu w powyższej konfiguracji `mypy` rozdzieliliśmy na dwa różne hooki startujące w innych folderach.

Po utworzeniu pliku `.pre-commit-config.yaml` należy uruchomić komendę:

```bash
pre-commit install
```

Wtedy w folderze `.git/hooks` powinny pojawić się hooki, które uruchamiają narzędzia zdefiniowane w pliku `.pre-commit-config.yaml`.

### Przetestowanie

Utwórzmy plik `first_package/__init__.py` i dodajmy do niego kod:
```python
import os
import sys

def insecure_function(user_input):
    os.system(f"rm -rf {user_input}")

user_input  = input( "Podaj ścieżkę do pliku: ") # bardzo dluuguuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuugi komentarz
insecure_function(user_input)
```

Dodajmy go do śledzenia przez git:
```bash
git add .
```

Teraz gdy spróbujemy wykonać commit, powinien się on nie wykonać póki nie naprawimy błędów:

```bash
git commit -m "Test"
git status
```
 

