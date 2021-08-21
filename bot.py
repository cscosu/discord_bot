# bot.py
import os
import random
import re
import string
import discord
import json
import aiohttp
from datetime import datetime, timedelta
from dotenv import load_dotenv
import jwt
from types import SimpleNamespace

# Email
import smtplib, ssl
port = 465  # For SSL

# Create a secure SSL context
context = ssl.create_default_context()


load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
JWT_SECRET = os.getenv('JWT_SECRET')
GUILD_ID = os.getenv('GUILD_ID')

DEBUG = os.getenv('DEBUG', False)

ENABLE_EMAIL_FALLBACK = os.getenv('ENABLE_EMAIL', False)

if DEBUG:
    # for test server
    OSU_AFFILIATION_ROLE_MAP = {
        "STUDENT": "876367912078802966",
        "FACULTY_STAFF": "876367955695398922",
        "ALUMNI": "876367987437887488"
    }
    API_URL = "http://localhost:8000"
else:
    OSU_AFFILIATION_ROLE_MAP = {
        "STUDENT": "876367122866008134",
        "FACULTY_STAFF": "876367196295663616",
        "ALUMNI": "876367661649506344"
    }
    API_URL = "https://auth.osucyber.club"

# For email fallback
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
    
    guild = client.get_guild(int(GUILD_ID))
    
    # TODO: For email fallback
    with open("schools.json", "r") as f:
        role_map_from_file = json.load(f)

@client.event
async def on_member_join(member):
    print(f'Sending message to {member.name}.')
    await member.create_dm()
    await member.dm_channel.send(
        f'Welcome to Cyber Security Club @ Ohio State!\n\nIf you are an OSU student, go to https://auth.osucyber.club to:\n- Link your Discord account. This will give you access to non-public channels.\n-Signup for the mailing list. (You can also signup at http://mailinglist.osucyber.club)\n\n'
    )

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    split = message.content.split(" ")
    if message.channel != message.author.dm_channel:
        # Try to avoid leaking tokens
        if len(split) > 0 and split[0] == "!connect":
            await message.delete()
            
            member = await guild.fetch_member(message.author.id)
            if member is not None:
                await member.create_dm()
                await member.dm_channel.send(f"DM me the message with !connect, don't post it publicly")
        return

    if len(split) == 2 and split[0] == "!connect":
        await check_osuauth_token_and_give_role(message.author, split[1])
        return

    # else:
    #     await parse_email_message(message)
    #     return

    await message.author.dm_channel.send("Bad message")

async def check_osuauth_token_and_give_role(user, token):
    new_token = jwt.encode({'discord_id': user.id, 'auth_token': token}, JWT_SECRET, algorithm="HS256")
    async with aiohttp.ClientSession() as session:
        payload = {'token': new_token}
        async with session.post(API_URL+'/internal/link_discord',
                            data=payload) as resp:
            if resp.status != 200:
                await user.dm_channel.send(f"bad token")
                return 

            result = await resp.json()
            print(str(result))

            if result['success']:
                aff = result['affiliation']
                if aff not in OSU_AFFILIATION_ROLE_MAP:
                    await user.dm_channel.send(f"Something went wrong, {result['affiliation']} does not have a discord role. Ask an officer!")
                    return
                role = OSU_AFFILIATION_ROLE_MAP[aff]
                member = await guild.fetch_member(user.id)
                if member is not None:
                    await member.add_roles(SimpleNamespace(**{"id": role})) # hack to avoid looking up role
                    await user.dm_channel.send("Successfully linked!")
            else:
                await user.dm_channel.send("Error: "+result['msg'])

# Email fallback stuff

def randomString(stringLength=40):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(stringLength))

def get_role_for_domain(domain):
    if domain in domain_role_map:
        return domain_role_map[domain]
    else:
        return None

# Email fallback token check (not currently used)
async def check_fallback_token_and_give_role(user, token):
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

# Email fallback; not currently used
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

# not currently used
def send_email(address, body):
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, address, body)

client.run(TOKEN)
