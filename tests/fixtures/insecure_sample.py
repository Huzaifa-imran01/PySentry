
import subprocess


def evaluate_expression(user_input):
    return eval(user_input)


def execute_command(user_input):
    subprocess.run(user_input, shell=True, check=True)
