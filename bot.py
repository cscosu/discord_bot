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
import json

# Email
import smtplib
import ssl

# Note to future maintainers: You really need to understand all of the code
# here before making changes. It is fragile, hacky, and it is very easy
# to introduce new bugs. Be very careful if the bot is ever going to
# send user-controlled data (see reaction roles code).

port = 465  # For SSL

# Create a secure SSL context
context = ssl.create_default_context()


load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
JWT_SECRET = os.getenv("JWT_SECRET")
GUILD_ID = os.getenv("GUILD_ID")
CTF_CATEGORY_ID = os.getenv("CTF_CATEGORY_ID")
CTF_ARCHIVE_CATEOGRY_ID = os.getenv("CTF_ARCHIVE_CATEOGRY_ID")

DEBUG = os.getenv("DEBUG", False)

ENABLE_EMAIL_FALLBACK = os.getenv("ENABLE_EMAIL", False)

if DEBUG:
    # for test server
    OSU_AFFILIATION_ROLE_MAP = {
        "STUDENT": "876367912078802966",
        "FACULTY_STAFF": "876367955695398922",
        "ALUMNI": "876367987437887488",
    }
    API_URL = "http://localhost:8000"
else:
    OSU_AFFILIATION_ROLE_MAP = {
        "STUDENT": "876367122866008134",
        "FACULTY_STAFF": "876367196295663616",
        "ALUMNI": "876367661649506344",
    }
    API_URL = "https://auth.osucyber.club"

# For email fallback
validation_tokens = {}  # TODO: use a DB
domain_role_map = {}

intents = discord.Intents.default()
intents.members = True
intents.reactions = True

client = discord.Client(intents=intents)

guild = None


@client.event
async def on_ready():
    global guild
    print(f"{client.user.name} has connected to Discord!")

    guild = client.get_guild(int(GUILD_ID))

    # TODO: For email fallback
    with open("schools.json", "r") as f:
        role_map_from_file = json.load(f)


@client.event
async def on_member_join(member):
    print(f"Sending message to {member.name}.")
    await member.create_dm()
    await member.dm_channel.send(
        f"Welcome to Cyber Security Club @ Ohio State!\n\nIf you are an OSU student, go to https://auth.osucyber.club to:\n- Link your Discord account. This will give you access to non-public channels.\n-Signup for the mailing list. (You can also signup at http://mailinglist.osucyber.club)\n\n"
    )


@client.event
async def on_message(message):
    if message.author == client.user:
        return

    split = message.content.split()
    print(f"{message.author.id} sent {split}")
    if message.channel != message.author.dm_channel and len(split) > 0:
        # Token was leaked in a public channel
        if split[0] == "!connect":
            if len(split) >= 2:
                # Here, we are going to submit the token for them anyway
                # since their token was already leaked :/
                #
                # There is still a small chance of race since this is all async
                # but i feel like social engineering is more likely to succeed
                # than the race.
                await check_osuauth_token_and_give_role(message.author, split[1])

            await message.delete()

            member = await guild.fetch_member(message.author.id)
            if member is not None:
                await member.create_dm()
                await member.dm_channel.send(
                    f"DM me the message with !connect, don't post it publicly"
                )
        if split[0] == "!competition" and len(split) == 5:
            if message.channel.category_id == CTF_CATEGORY_ID and check_has_role(message.author, "Officers"):
                # Step 1: Make the main channel for the CTF
                title, description, username, password = split[1:5]
                channel = await message.channel.category.create_text_channel(
                    title,
                    position=0,
                    topic=f"{title}\n==========\n{description}\n==========\nusername: {username}\n==========\nOfficers, type !archive to archive this channel.",
                )
                embed = discord.Embed(title=title, description=description, color=0xbb0000)
                for k, v in zip(("Username", "Password"), (f"`{username}`", f"`{password}`")):
                    embed.add_field(name=k, value=v, inline=False)
                pinmessage = await channel.send(embed=embed)

                # Step 2: Make the category for the CTF
                ctf = message.channel.name
                cat = None
                live_ctf_position = 0

                for category in client.guild.categories:
                    if live_ctf_position <= 0:
                        live_ctf_position += -1
                    if category.id == CTF_CATEGORY_ID:
                        live_ctf_position *= -1
                
                permissions = message.channel.overwrites
                cat = await client.guild.create_category(
                    title.lower() + " challenges",
                    overwrites=permissions,
                    position=live_ctf_position,
                )

                await pinmessage.pin()
                await message.delete()
                return
            await message.channel.send(
                embed=discord.utils.create_embed("You need to be an officer in the CTF category")
            )
            return
        if split[0] == "!chal":
            if message.channel.category_id == CTF_CATEGORY_ID:
                if len(split) == 1:
                    await message.channel.send(
                        embed=discord.utils.create_embed("Must provide a challenge name")
                    )
                    return
                if len(split) != 2:
                    await message.channel.send(
                        embed=discord.utils.create_embed("There can be no spaces in the challenge name")
                    )
                    return
                ctf_name = message.channel.name.lower()
                chal_name = split[1]
                for category in client.guild.categories:
                    if category.name == ctf_name + " challenges":
                        for chan in category.text_channels:
                            if chan.name.lower() == chal_name.lower():
                                await message.channel.send(
                                    embed=discord.utils.create_embed(
                                        f"A channel for this challenge has already been created! Click [here](https://discordapp.com/channels/{GUILD_ID}/{chan.id}/) to join the discussion."
                                    )
                                )
                                return
                        chan = await category.create_text_channel(
                            chal_name,
                            position=len(category.text_channels),
                            topic=f"{message.channel.name}: {chal_name}",
                        )
                        await message.channel.send(
                            embed=discord.utils.create_embed(
                                f"Channel created! Click [here](https://discordapp.com/channels/{GUILD_ID}/{chan.id}/) to go there."
                            )
                        )
                        return
                await message.channel.send(
                    embed=discord.utils.create_embed(
                        f"Could not find the category for this CTF"
                    )
                )
        if split[0] == "!archive":
            if message.channel.category_id == CTF_CATEGORY_ID:
                for category, chal_channels in client.guild.by_category():
                    if message.channel.name.lower() + " challenges" == category.name.lower():
                        for channel in chal_channels:
                            await archive_channel(channel, message.channel)
                        break

                await message.channel.edit(category=CTF_ARCHIVE_CATEOGRY_ID)
                await message.channel.edit(position=0)
            elif message.channel.category.name.endswith(" challenges"):
                ctf = message.channel.category.name[:-len(" challenges")].replace(" ", "-")
                for chan in client.ctfs.text_channels:
                    if chan.name.lower() == ctf.lower():
                        await archive_channel(message.channel, chan)
                        return
                
                await message.channel.send(
                    embed=discord.utils.create_embed(f"Could not find live CTF channel {ctf}. Was it accidentally moved?")
                )            
            return
        return
        

    if len(split) == 2 and split[0] == "!connect":
        await check_osuauth_token_and_give_role(message.author, split[1])
        return

    if len(split) > 0 and split[0] == "!reaction_role":
        await make_reaction_role(message)
        return

    # else:
    #     await parse_email_message(message)
    #     return

    await message.author.dm_channel.send("Bad message")

async def archive_channel(channel, ctf_channel):
    fname = f"{ctf_channel.name}_{channel.name}_log.txt"
    f = open(fname, "w")
    async for m in channel.history(limit=10000, oldest_first=True):
        f.write(f"[{m.created_at.replace().strftime('%Y-%m-%d %I:%M %p')} UTC] {m.author.display_name}: {m.content}\n{' '.join(map(lambda x: x.url, m.attachments))}\n")
    f.close()

    f = open(fname, "rb")
    await ctf_channel.send(
        embed = discord.utils.create_embed(f"Discussion for the challenge {channel.name} has been archived. A text log of the conversation is attached."),
        file = discord.File(f)
    )
    f.close()

    os.remove(fname)

    cat = channel.category
    await channel.delete()
    if len(cat.text_channels) == 0:
        await cat.delete()


async def check_has_role(member, role_name):
    roles = member.roles
    for role in roles:
        if role.name == role_name:
            return True
    return False

async def make_reaction_role(message):
    if message.author.id != 633048088965021697:
        await message.channel.send("Not authorized")

    split = message.content.split()

    try:
        channel_id = int(split[1])
        channel = discord.utils.get(guild.channels, id=channel_id)

        i = message.content.find("```json")
        data = message.content[i:]
        data = data[len("```json\n"):]
        data = data[: -len("```")]
        data = json.loads(data)

        res = "**React to this message to get roles!**\n"
        for reaction, role in data.items():
            res += f"{reaction} {role}\n"

        new_message = await channel.send(res.strip())

        for reaction in data:
            await new_message.add_reaction(reaction)

    except ValueError as e:
        await message.channel.send(e)


@client.event
async def on_raw_reaction_add(event):
    emoji = event.emoji
    channel = discord.utils.get(guild.channels, id=event.channel_id)
    message = await channel.fetch_message(event.message_id)
    user = client.get_user(event.user_id)
    member = event.member

    # This is dangerous -- we better not ever let this bot send
    # user-controlled data...
    if (
        message.author != client.user
        or not message.content.startswith(
            "**React to this message to get roles!**\n"
        )
        or user == client.user
    ):
        return

    lines = message.content.split("\n")[1:]
    for line in lines:
        line_reaction, role_name = line.strip().split(" ", 1)

        if str(emoji) == line_reaction:
            role = discord.utils.get(guild.roles, name=role_name)
            if not member:
                member = guild.get_member(user.id)

            if member:
                await member.add_roles(role)


@client.event
async def on_raw_reaction_remove(event):
    emoji = event.emoji
    channel = discord.utils.get(guild.channels, id=event.channel_id)
    message = await channel.fetch_message(event.message_id)
    user = client.get_user(event.user_id)
    member = event.member

    if (
        message.author != client.user
        or not message.content.startswith(
            "**React to this message to get roles!**\n"
        )
        or user == client.user
    ):
        return

    lines = message.content.split("\n")[1:]
    for line in lines:
        line_reaction, role_name = line.strip().split(" ", 1)

        if str(emoji) == line_reaction:
            role = discord.utils.get(guild.roles, name=role_name)
            if not member:
                member = guild.get_member(user.id)

            if member:
                await member.remove_roles(role)


async def check_osuauth_token_and_give_role(user, token):
    new_token = jwt.encode(
        {"discord_id": user.id, "auth_token": token}, JWT_SECRET, algorithm="HS256"
    )
    async with aiohttp.ClientSession() as session:
        payload = {"token": new_token}
        async with session.post(
            API_URL + "/internal/link_discord", data=payload
        ) as resp:
            if resp.status != 200:
                await user.dm_channel.send(f"bad token")
                return

            result = await resp.json()
            print(str(result))

            if result["success"]:
                aff = result["affiliation"]
                if aff not in OSU_AFFILIATION_ROLE_MAP:
                    await user.dm_channel.send(
                        f"Something went wrong, {result['affiliation']} does not have a discord role. Ask an officer!"
                    )
                    return
                role = OSU_AFFILIATION_ROLE_MAP[aff]
                member = await guild.fetch_member(user.id)
                if member is not None:
                    await member.add_roles(
                        SimpleNamespace(**{"id": role})
                    )  # hack to avoid looking up role
                    await user.dm_channel.send("Successfully linked!")
            else:
                await user.dm_channel.send("Error: " + result["msg"])


# Email fallback stuff


def randomString(stringLength=40):
    letters = string.ascii_letters + string.digits
    return "".join(random.choice(letters) for i in range(stringLength))


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
            await message.author.dm_channel.send(
                "We already sent you an email! Wait 1hr."
            )
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
        validation_tokens[message.author.id] = (
            random_token,
            role,
            datetime.now() + timedelta(hours=1),
        )
        send_email(
            message.content,
            """Subject: Discord Bot .edu Email Verification

Please reply to the discord bot with the following:

token_"""
            + random_token,
        )
        await message.author.dm_channel.send("Check your email.")

    else:
        await message.author.dm_channel.send(
            "Email domain is not known. Message admins for help."
        )
        return


# not currently used
def send_email(address, body):
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, address, body)


client.run(TOKEN)
