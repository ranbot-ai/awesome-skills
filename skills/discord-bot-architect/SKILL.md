---
name: discord-bot-architect
description: Specialized skill for building production-ready Discord bots. Covers Discord.js (JavaScript) and Pycord (Python), gateway intents, slash commands, interactive components, rate limiting, and sharding. 
category: Development & Code Tools
source: antigravity
tags: [python, javascript, typescript, node, api, ai, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/discord-bot-architect
---


# Discord Bot Architect

## Patterns

### Discord.js v14 Foundation

Modern Discord bot setup with Discord.js v14 and slash commands

**When to use**: ['Building Discord bots with JavaScript/TypeScript', 'Need full gateway connection with events', 'Building bots with complex interactions']

```javascript
```javascript
// src/index.js
const { Client, Collection, GatewayIntentBits, Events } = require('discord.js');
const fs = require('node:fs');
const path = require('node:path');
require('dotenv').config();

// Create client with minimal required intents
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    // Add only what you need:
    // GatewayIntentBits.GuildMessages,
    // GatewayIntentBits.MessageContent,  // PRIVILEGED - avoid if possible
  ]
});

// Load commands
client.commands = new Collection();
const commandsPath = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsPath).filter(f => f.endsWith('.js'));

for (const file of commandFiles) {
  const filePath = path.join(commandsPath, file);
  const command = require(filePath);
  if ('data' in command && 'execute' in command) {
    client.commands.set(command.data.name, command);
  }
}

// Load events
const eventsPath = path.join(__dirname, 'events');
const eventFiles = fs.readdirSync(eventsPath).filter(f => f.endsWith('.js'));

for (const file of eventFiles) {
  const filePath = path.join(eventsPath, file);
  const event = require(filePath);
  if (event.once) {
    client.once(event.name, (...args) => event.execute(...args));
  } else {
    client.on(event.name, (...args) => event.execute(...args));
  }
}

client.login(process.env.DISCORD_TOKEN);
```

```javascript
// src/commands/ping.js
const { SlashCommandBuilder } = require('discord.js');

module.exports = {
  data: new SlashCommandBuilder()
    .setName('ping')
    .setDescription('Replies with Pong!'),

  async execute(interaction) {
    const sent = await interaction.reply({
      content: 'Pinging...',
      fetchReply: true
    });

    const latency = sent.createdTimestamp - interaction.createdTimestamp;
    await interaction.editReply(`Pong! Latency: ${latency}ms`);
  }
};
```

```javascript
// src/events/interactionCreate.js
const { Events } = require('discord.js');

module.exports = {
  name: Event
```

### Pycord Bot Foundation

Discord bot with Pycord (Python) and application commands

**When to use**: ['Building Discord bots with Python', 'Prefer async/await patterns', 'Need good slash command support']

```python
```python
# main.py
import os
import discord
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

# Configure intents - only enable what you need
intents = discord.Intents.default()
# intents.message_content = True  # PRIVILEGED - avoid if possible
# intents.members = True          # PRIVILEGED

bot = commands.Bot(
    command_prefix="!",  # Legacy, prefer slash commands
    intents=intents
)

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user}")
    # Sync commands (do this carefully - see sharp edges)
    # await bot.sync_commands()

# Slash command
@bot.slash_command(name="ping", description="Check bot latency")
async def ping(ctx: discord.ApplicationContext):
    latency = round(bot.latency * 1000)
    await ctx.respond(f"Pong! Latency: {latency}ms")

# Slash command with options
@bot.slash_command(name="greet", description="Greet a user")
async def greet(
    ctx: discord.ApplicationContext,
    user: discord.Option(discord.Member, "User to greet"),
    message: discord.Option(str, "Custom message", required=False)
):
    msg = message or "Hello!"
    await ctx.respond(f"{user.mention}, {msg}")

# Load cogs
for filename in os.listdir("./cogs"):
    if filename.endswith(".py"):
        bot.load_extension(f"cogs.{filename[:-3]}")

bot.run(os.environ["DISCORD_TOKEN"])
```

```python
# cogs/general.py
import discord
from discord.ext import commands

class General(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.slash_command(name="info", description="Bot information")
    async def info(self, ctx: discord.ApplicationContext):
        embed = discord.Embed(
            title="Bot Info",
            description="A helpful Discord bot",
            color=discord.Color.blue()
        )
        embed.add_field(name="Servers", value=len(self.bot.guilds))
        embed.add_field(name="Latency", value=f"{round(self.bot.latency * 1000)}ms")
        await ctx.respond(embed=embed)

    @commands.Cog.
```

### Interactive Components Pattern

Using buttons, select menus, and modals for rich UX

**When to use**: ['Need interactive user interfaces', 'Collecting user input beyond slash command options', 'Building menus, confirmations, or forms']

```python
```javascript
// Discord.js - Buttons and Select Menus
const {
  SlashCommandBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  StringSelectMenuBuilder,
  ModalBuilder,
  TextInputBuilder,
  TextInput
