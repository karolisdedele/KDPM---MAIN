import random
import string

def pw_generator(password_length, use_special_characters, number_of_special_chars):
    password = []
    if use_special_characters:
        password.extend([random.choice(string.punctuation) for i in range(number_of_special_chars)])
        password_length -= number_of_special_chars
    password.extend([random.choice(string.ascii_letters + string.digits) for i in range(password_length)])
    random.shuffle(password)
    return ''.join(password)
