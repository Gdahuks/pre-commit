import os


def insecure_function(user_input):
    os.system(f"rm -rf {user_input}")

user_input = input("Podaj ścieżkę do pliku: ")
insecure_function(user_input)