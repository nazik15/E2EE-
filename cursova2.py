import telebot
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import os

# Вставте ваш токен сюди
API_TOKEN = '6671116245:AAG26HWLlpYyLgrfH8EHggPZmoAUkJa0lqw'

# Створення асиметричних ключів
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# Ініціалізація бота
bot = telebot.TeleBot(API_TOKEN)


def encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()


def decrypt_message(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


def save_message_to_file(chat_id, username, message):
    filename = f"chat_{chat_id}.txt"
    with open(filename, 'a') as file:
        file.write(f"{username}: {message}\n")


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Hello! Send me a message and I'll encrypt it using an asymmetric key. Use /decrypt <message> to decrypt a message.")


@bot.message_handler(commands=['decrypt'])
def decrypt_command(message):
    try:
        encrypted_message = message.text.split(' ', 1)[1]
        try:
            decrypted_message = decrypt_message(private_key, encrypted_message)
            bot.reply_to(message, f"Decrypted message: {decrypted_message}")
        except Exception:
            bot.reply_to(message, "Can not decode message")
    except IndexError:
        bot.reply_to(message, "Please provide a message to decrypt.")
    except Exception as e:
        bot.reply_to(message, f"An error occurred: {e}")


@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    username = message.from_user.username if message.from_user.username else f"{message.from_user.first_name} {message.from_user.last_name}"
    try:
        encrypted_message = encrypt_message(public_key, message.text)
        save_message_to_file(message.chat.id, username, f"Text: {message.text}")
        save_message_to_file(message.chat.id, username, f"Encrypted: {encrypted_message}")
        bot.reply_to(message, encrypted_message)
    except Exception as e:
        error_message = "An error occurred while encrypting the message. Can not decode message."
        save_message_to_file(message.chat.id, username, f"Error: {str(e)}")
        bot.reply_to(message, error_message)


if __name__ == '__main__':
    bot.polling(none_stop=True)
