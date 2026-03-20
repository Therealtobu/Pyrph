"""
Pyrph – Discord Obfuscation Bot  (V4 – Parallel Dual-Engine)
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

intents = discord.Intents.default()
intents.message_content = True
bot      = commands.Bot(command_prefix="!", intents=intents)
pipeline = ObfuscationPipeline()

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  P Y R P H  v4  •  God-Tier Python Obfuscator           ║
║  Parallel Dual-Engine  •  9.5 Stages  •  Rust Native    ║
╚══════════════════════════════════════════════════════════╝
""".strip()


@bot.event
async def on_ready():
    await bot.tree.sync()
    from native_bridge import status as _ncs
    print(f"[Pyrph] Logged in as {bot.user} (id={bot.user.id})")
    print(BANNER)
    print(f"[Pyrph] {_ncs()}")


@bot.tree.command(name="obfuscate", description="Obfuscate a Python (.py) file")
@app_commands.describe(file="The .py file to obfuscate")
async def obfuscate(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)

    if not file.filename.endswith(".py"):
        await interaction.followup.send("❌ Only `.py` files are accepted.", ephemeral=True)
        return

    if file.size > config.MAX_FILE_SIZE:
        await interaction.followup.send(
            f"❌ File too large. Max size: {config.MAX_FILE_SIZE // 1024} KB.",
            ephemeral=True,
        )
        return

    try:
        raw    = await file.read()
        source = raw.decode("utf-8")
    except Exception as e:
        await interaction.followup.send(f"❌ Could not read file: `{e}`", ephemeral=True)
        return

    try:
        loop   = asyncio.get_event_loop()
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

    out_name  = file.filename.replace(".py", "_pyrph.py")
    out_bytes = result.encode("utf-8")
    out_file  = discord.File(io.BytesIO(out_bytes), filename=out_name)

    from native_bridge import NATIVE_AVAILABLE
    native_badge = "🦀 Rust" if NATIVE_AVAILABLE else "🐍 Python"

    embed = discord.Embed(
        title="✅ Obfuscation Complete",
        color=0x00FF88,
        description=(
            f"**Input:** `{file.filename}` ({file.size:,} bytes)\n"
            f"**Output:** `{out_name}` ({len(out_bytes):,} bytes)\n\n"
            f"**Engine:** {native_badge} | 9.5 Stages active\n"
            "Pipeline: **Normalize → Transform → IR → SAG → "
            "Metamorphic → VM3 → PostVM → VM4 → Parallel**"
        ),
    )
    embed.set_footer(text="Pyrph • God-Tier Python Obfuscator")
    await interaction.followup.send(embed=embed, file=out_file)


@bot.tree.command(name="info", description="Show Pyrph pipeline info")
async def info(interaction: discord.Interaction):
    from native_bridge import status as _ncs, NATIVE_AVAILABLE
    _nt = "🦀 Rust NATIVE (pyrph_core.so)" if NATIVE_AVAILABLE else "🐍 Python fallback (no .so)"
    embed = discord.Embed(
        title="Pyrph v4 – Pipeline Info",
        color=0x5865F2,
        description=(
            "**Native Core:** `" + _nt + "`\n\n"
            "```\n"
            "Stage 1    AST Normalize\n"
            "           Lambda · Comprehension · Ternary · Sugar\n\n"
            "Stage 2    AST Transform\n"
            "           CFF · MBA · StringLift · ConstVirt\n"
            "           FuncSplit · OpaquePredicates\n\n"
            "Stage 3    IR Generation\n"
            "           50+ opcodes · CFG · Def-use chains\n\n"
            "Stage 4    IR Obfuscation (7 passes)\n"
            "           ImportObf · SemanticFP · Substitution\n"
            "           Shuffler · Rewriter · Encryptor · MCP\n\n"
            "Stage 4.5  Semantic Alias Graph (SAG)\n"
            "           Multi-source aliases · Observer effect\n"
            "           Cross-variable cycles (anti-SSA)\n\n"
            "Stage 5    Metamorphic Engine\n"
            "           3 variants/fn · 6 micro-transforms\n"
            "           hash(session_key, args, counter) dispatch\n\n"
            "Stage 6    VM3 (Poly-Triple-Layer)\n"
            "           VM1+VM2+VM3 · AC-wave scheduler\n"
            "           Split-state regs (_SS) · ICV chain\n"
            "           Polymorphic resolver (no static map)\n"
            "           Anti-snapshot · Env check · StrFrag\n\n"
            "Stage 7    Post-VM Protection\n"
            "           PDL → TBL → OEL → DLI → PEIL\n\n"
            "Stage 8    VM4 Fragment Graph\n"
            "           FG · Fabric · State Mesh · DNA Lock\n\n"
            "Stage 9    Native Rust (pyrph_core.so)\n"
            "           resolver · SS regs · sched · peil · dna\n\n"
            "Stage 9.5  Parallel Dual-Engine\n"
            "           Mode 1: Thread parallel\n"
            "           Mode 2: Process parallel (IPC)\n"
            "           Mode 3: Interleaved (cross-key dep)\n"
            "           combine(vm3, rust_confirm, cross_key)\n"
            "```"
        ),
    )
    embed.set_footer(text="Pyrph • God-Tier Python Obfuscator")
    await interaction.response.send_message(embed=embed)


if __name__ == "__main__":
    if not config.DISCORD_TOKEN:
        raise RuntimeError("DISCORD_TOKEN env var not set.")
    bot.run(config.DISCORD_TOKEN)
