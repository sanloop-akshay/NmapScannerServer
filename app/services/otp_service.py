from random import randint

def generate_otp() -> str:
    return str(randint(100000, 999999))