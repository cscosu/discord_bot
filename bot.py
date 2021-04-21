# bot.py
import os
import random
import asyncio
import re
import string
import discord
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Email
import smtplib, ssl
port = 465  # For SSL

# Create a secure SSL context
context = ssl.create_default_context()


load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')


validation_tokens = {} # TODO: use a DB
domain_role_map = {}

intents = discord.Intents.default()
intents.members = True

client = discord.Client(intents=intents)

guild = None
@client.event
async def on_ready():
    global guild
    print(f'{client.user.name} has connected to Discord!')
    # Only supports one guild
    guild = await client.fetch_guilds().get()
    with open("schools.json", "r") as f:
        role_map_from_file = json.load(f)

    actual_roles = await guild.fetch_roles()
    # This is a terrible n^2 way of matching roles
    # in the discord org to role names in the config
    # file. It's fine cause it happens once and n is
    # relatively small.
    for domain, role_name in role_map_from_file.items():
        # Find the matching role in the list of actual roles
        for actual_role in actual_roles:
            if actual_role.name == role_name:
                domain_role_map[domain] = actual_role
                break
        if domain not in domain_role_map:
            print("Could not find matching role for "+str(role_name))

@client.event
async def on_member_join(member):
    print(f'Sending message to {member.name}.')
    await member.create_dm()
    await member.dm_channel.send(
        f'Send me your .edu email address to get a role in {guild.name}'
    )

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.channel != message.author.dm_channel:
        return

    if message.content[0:6] == "token_":
        split = message.content.split("_")
        if len(split) == 2 and split[0] == "token":
            await check_token_and_give_role(message.author, split[1])
            return
    else:
        await parse_email_message(message)
        return

    await message.author.dm_channel.send("Bad message")

def randomString(stringLength=40):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(stringLength))

def get_role_for_domain(domain):
    if domain in domain_role_map:
        return domain_role_map[domain]
    else:
        return None

async def check_token_and_give_role(user, token):
    if user.id not in validation_tokens:
        await user.dm_channel.send("No awaiting validation")
        return

    validation = validation_tokens[user.id]
    if validation[0] == token:
        # Valid token
        member = await guild.fetch_member(user.id)
        if member:
            await member.add_roles(validation[1])
            await user.dm_channel.send("done")
            del validation_tokens[user.id]
        else:
            await user.dm_channel.send("failed. dm admins")
    else:
        await user.dm_channel.send("bad token")

async def parse_email_message(message):
    # Rate limit: 1 request per hour
    if message.author.id in validation_tokens:
        expire = validation_tokens[message.author.id][2]
        if datetime.now() > expire:
            del validation_tokens[message.author.id]
        else:
            await message.author.dm_channel.send("We already sent you an email! Wait 1hr.")
            return

    # Verify that the message was actually an email address
    email_regex = re.compile("^[A-Za-z0-9\.\-\_]+@[A-Za-z\.\-]+.edu$")
    email_split = message.content.split("@")
    if not email_regex.match(message.content) or len(email_split) != 2:
        await message.author.dm_channel.send("invalid email")
        return

    # The role will be stored in a tuple with the token and expiration date
    domain = email_split[1]
    role = get_role_for_domain(domain)
    if role:
        random_token = randomString()
        validation_tokens[message.author.id] = (random_token, role, datetime.now() + timedelta(hours=1) )
        send_email(message.content, """Subject: Discord Bot .edu Email Verification

Please reply to the discord bot with the following:

token_"""+random_token)
        await message.author.dm_channel.send("Check your email.")

    else:
        await message.author.dm_channel.send("Email domain is not known. Message admins for help.")
        return

def send_email(address, body):
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, address, body)

client.run(TOKEN)
