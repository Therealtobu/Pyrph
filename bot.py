"""
Pyrph – Discord Obfuscation Bot
Entry point: handles slash commands, file upload/download, and pipeline dispatch.
"""
import asyncio
import io
import os
import tempfile
import traceback

import discord
from discord import app_commands
from discord.ext import commands

import config
from pipeline import ObfuscationPipeline

# ──────────────────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)
pipeline = ObfuscationPipeline()

BANNER = """
╔══════════════════════════════════════════╗
║   P Y R P H  •  Python Obfuscator v1.0  ║
║   Poly-Triple-Layer VM  •  AST+IR+VM     ║
╚══════════════════════════════════════════╝
""".strip()

# ──────────────────────────────────────────────────────────────────────────────
@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"[Pyrph] Logged in as {bot.user} (id={bot.user.id})")
    print(BANNER)


# ──────────────────────────────────────────────────────────────────────────────
@bot.tree.command(name="obfuscate", description="Obfuscate a Python (.py) file")
@app_commands.describe(file="The .py file to obfuscate")
async def obfuscate(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)

    # ── Validate ──────────────────────────────────────────────────────────────
    if not file.filename.endswith(".py"):
        await interaction.followup.send(
            "❌ Only `.py` files are accepted.", ephemeral=True
        )
        return

    if file.size > config.MAX_FILE_SIZE:
        await interaction.followup.send(
            f"❌ File too large. Max size: {config.MAX_FILE_SIZE // 1024} KB.",
            ephemeral=True,
        )
        return

    # ── Read source ───────────────────────────────────────────────────────────
    try:
        raw = await file.read()
        source = raw.decode("utf-8")
    except Exception as e:
        await interaction.followup.send(f"❌ Could not read file: `{e}`", ephemeral=True)
        return

    # ── Run pipeline (with timeout) ───────────────────────────────────────────
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, pipeline.run, source),
            timeout=config.OBFUSCATION_TIMEOUT,
        )
    except asyncio.TimeoutError:
        await interaction.followup.send(
            "⏱️ Obfuscation timed out. File may be too complex.", ephemeral=True
        )
        return
    except Exception:
        tb = traceback.format_exc()
        await interaction.followup.send(
            f"❌ Pipeline error:\n```\n{tb[:1800]}\n```", ephemeral=True
        )
        return

    # ── Send result ───────────────────────────────────────────────────────────
    out_name = file.filename.replace(".py", "_pyrph.py")
    out_bytes = result.encode("utf-8")
    out_file = discord.File(io.BytesIO(out_bytes), filename=out_name)

    embed = discord.Embed(
        title="✅ Obfuscation Complete",
        color=0x00FF88,
        description=(
            f"**Input:** `{file.filename}` ({file.size:,} bytes)\n"
            f"**Output:** `{out_name}` ({len(out_bytes):,} bytes)\n\n"
            "Pipeline: **AST Normalize → AST Transform → IR Gen → IR Obf → VM3**"
        ),
    )
    embed.set_footer(text="Pyrph • Poly-Triple-Layer VM Obfuscator")
    await interaction.followup.send(embed=embed, file=out_file)


# ──────────────────────────────────────────────────────────────────────────────
@bot.tree.command(name="info", description="Show Pyrph pipeline info")
async def info(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Pyrph Pipeline",
        color=0x5865F2,
        description=(
            "```\n"
            "1. AST Normalize\n"
            "   ├─ Lambda inliner\n"
            "   ├─ Comprehension expander\n"
            "   ├─ Ternary expander\n"
            "   └─ Syntactic sugar remover\n\n"
            "2. AST Transform\n"
            "   ├─ Control Flow Flattening (state machine)\n"
            "   ├─ MBA Expression Expansion\n"
            "   ├─ String Lifting → table\n"
            "   ├─ Constant Virtualization\n"
            "   ├─ Function Splitting (dispatcher)\n"
            "   └─ Opaque Predicates\n\n"
            "3. IR Generation\n"
            "   ├─ Instruction-level IR nodes\n"
            "   ├─ Control Flow Graph\n"
            "   └─ Dependency Graph\n\n"
            "4. IR Obfuscation\n"
            "   ├─ Instruction Substitution\n"
            "   ├─ Instruction Shuffler + Jump Table\n"
            "   ├─ Control Flow Rewriter\n"
            "   └─ Block Encryptor\n\n"
            "5. VM (Poly-Triple-Layer)\n"
            "   ├─ VM1: Stack+Register hybrid (inner)\n"
            "   ├─ VM2: Side VM (different logic)\n"
            "   ├─ VM3: Merged opcode executor\n"
            "   ├─ AC-wave + PRNG + data scheduler\n"
            "   ├─ Instruction interleaving (split ADD→VM1+VM2)\n"
            "   ├─ Cross-key dependency (VM1↔VM2)\n"
            "   └─ Polymorphic opcode resolver (no static map)\n"
            "```"
        ),
    )
    await interaction.response.send_message(embed=embed)


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not config.DISCORD_TOKEN:
        raise RuntimeError("DISCORD_TOKEN env var not set.")
    bot.run(config.DISCORD_TOKEN)
