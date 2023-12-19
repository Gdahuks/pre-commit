import os
import sys


def insecure_function(user_input):
    os.system(f"rm -rf {user_input}")


user_input = input(
    "Podaj ścieżkę do pliku: "
)  # bardzo dluuguuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuugi komentarz
insecure_function(user_input)
