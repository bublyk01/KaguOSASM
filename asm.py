#!/usr/bin/env python3

import sys
import os
import re
import shlex

INSTR_COPY_FROM_TO_ADDRESS = "1"
INSTR_JUMP = "3"
INSTR_JUMP_IF = "4"
INSTR_JUMP_IF_NOT = "5"
INSTR_JUMP_ERR = "6"
INSTR_CPU_EXEC = "0"

KERNEL_START = 41
GLOBAL_KERNEL_DISK = "build/kernel.disk"
GLOBAL_USER_DISK = "build/user.disk"
GLOBAL_RAM_SIZE = 1024

DEBUG_INFO = int(os.getenv("DEBUG_INFO", 1))
USER_SPACE = int(os.getenv("USER_SPACE", 0))

FIRST_INSTRUCTION_NO = 17 if USER_SPACE else KERNEL_START
OUTPUT_FILE = GLOBAL_USER_DISK if USER_SPACE else GLOBAL_KERNEL_DISK

COMPILATION_ERROR_COUNT = 0
LABELS, LABELS_ADDRESSES = [], []
CONSTANTS, CONSTANTS_EVALUATED, CONSTANTS_ADDRESSES = [], [], []
VARIABLES, VARIABLES_ADDRESSES, VARIABLES_DECL_ADDRESSES = [], [], []
PARSED_LEXEMES = []
NEXT_INSTR_ADDRESS = FIRST_INSTRUCTION_NO

CMDS_ARRAY = ["write", "copy", "label", "jump", "jump_if", "jump_if_not", "jump_err", "cpu_exec", "var", "DEBUG_ON", "DEBUG_OFF"]

def load_symbol_table():
    symbol_table = {}
    include_files = ["include/operations.sh", "include/syscalls.sh", "include/registers.sh"]
    for file in include_files:
        if not os.path.isfile(file): continue
        with open(file) as f:
            for line in f:
                match = re.match(r'export\s+([A-Z0-9_]+)=(\d+)', line.strip())
                if match:
                    name, val = match.groups()
                    symbol_table[name] = val
    return symbol_table

SYMBOL_TABLE = load_symbol_table()

def is_command(word): return word in CMDS_ARRAY

def compilation_error(expected, info="", line="", line_no="", filename=""):
    global COMPILATION_ERROR_COUNT
    print(f"\033[93mCompilation error\033[0m at {filename}:{line_no}", file=sys.stderr)
    print(f"\033[91m{line}\033[0m", file=sys.stderr)
    if info:
        print(f"\033[91m{info}\033[0m", file=sys.stderr)
    print(f"Expected syntax:\n\033[92m{expected}\033[0m\n", file=sys.stderr)
    COMPILATION_ERROR_COUNT += 1
    if COMPILATION_ERROR_COUNT > 20:
        print("Too many compilation errors, aborting", file=sys.stderr)
        sys.exit(1)

def parse_lexeme(lex):
    if not lex or lex.startswith("//"): return "_ cmt"
    prefix = "_"
    if lex[0] in ("@", "*"): prefix, lex = lex[0], lex[1:]
    if lex.startswith('"') and lex.endswith('"'):
        return f"{prefix} str {lex[1:-1]}"
    if lex == "to": return f"{prefix} kto =>"
    if re.match(r"^[0-9]+$", lex): return f"{prefix} num {lex}"
    if lex.startswith("var:"):
        name = lex[4:]
        return f"{prefix} var {name}" if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name) else f"{prefix} err name_format {lex}"
    if lex.startswith("label:"):
        name = lex[6:]
        return f"{prefix} lbl {name}" if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name) else f"{prefix} err name_format {lex}"
    if lex.startswith("OP_"): return f"{prefix} opr {lex}"
    if lex.startswith("SYS_CALL_"): return f"{prefix} sys {lex}"
    if (lex.startswith("REG_") or lex.startswith("INFO_") or lex in ("DISPLAY_BUFFER", "DISPLAY_COLOR", "DISPLAY_BACKGROUND", "KEYBOARD_BUFFER", "PROGRAM_COUNTER") or lex.startswith("FREE_")):
        return f"{prefix} reg {lex}"
    if lex.startswith("COLOR_"): return f"{prefix} clr {lex}"
    if lex in ("KEYBOARD_READ_LINE", "KEYBOARD_READ_LINE_SILENTLY", "KEYBOARD_READ_CHAR", "KEYBOARD_READ_CHAR_SILENTLY"):
        return f"{prefix} mod {lex}"
    if is_command(lex): return f"{prefix} cmd {lex}"
    if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", lex): return f"{prefix} nam {lex}"
    return f"{prefix} err other {lex}"

def find_index(value, array): return array.index(value) if value in array else -1

INSTRUCTION_RULES = {
    "write": {"count": 4, "pattern": re.compile(r"^(_ cmd)(_ str|_ num|_ opr|_ sys|_ clr|_ mod|_ lbl)(_ kto)(_ num|\* num|_ reg|\* reg|_ var|\* var)(_ cmt)$"), "syntax": "write \"some string\" to address OR write OP_* to address"},
    "copy": {"count": 4, "pattern": re.compile(r"^(_ cmd)(_ num|\* num|_ reg|\* reg|_ var|\* var|@ var)(_ kto)(_ num|\* num|_ reg|\* reg|_ var|\* var)(_ cmt)$"), "syntax": "copy someAddress to otherAddress"},
    "label": {"count": 2, "pattern": re.compile(r"^(_ cmd)(_ nam)(_ cmt)$"), "syntax": "label name"},
    "var": {"count": 2, "pattern": re.compile(r"^(_ cmd)(_ nam)(_ cmt)$"), "syntax": "var name"},
    "jump": {"count": 2, "pattern": re.compile(r"^(_ cmd)(_ num|\* num|\* reg|_ lbl|\* var)(_ cmt)$"), "syntax": "jump label:someName"},
    "jump_if": {"count": 2, "pattern": re.compile(r"^(_ cmd)(_ num|\* num|\* reg|_ lbl|\* var)(_ cmt)$"), "syntax": "jump_if label:someName"},
    "jump_if_not": {"count": 2, "pattern": re.compile(r"^(_ cmd)(_ num|\* num|\* reg|_ lbl|\* var)(_ cmt)$"), "syntax": "jump_if_not label:someName"},
    "jump_err": {"count": 2, "pattern": re.compile(r"^(_ cmd)(_ num|\* num|\* reg|_ lbl|\* var)(_ cmt)$"), "syntax": "jump_err label:someName"},
    "cpu_exec": {"count": 1, "pattern": re.compile(r"^(_ cmd)(_ cmt)$"), "syntax": "cpu_exec"},
    "DEBUG_ON": {"count": 1, "pattern": re.compile(r"^(_ cmd)(_ cmt)$"), "syntax": "DEBUG_ON"},
    "DEBUG_OFF": {"count": 1, "pattern": re.compile(r"^(_ cmd)(_ cmt)$"), "syntax": "DEBUG_OFF"},
}

SRC_FILES = []
for arg in sys.argv[1:]:
    if not os.path.isfile(arg):
        print(f"{arg} is not a valid source file", file=sys.stderr)
        sys.exit(1)
    SRC_FILES.append(arg)

for src_file in SRC_FILES:
    with open(src_file, "r") as f:
        PARSED_LEXEMES.append(f"file {src_file}")
        for lineno, line in enumerate(f, start=1):
            line = line.split("//")[0].strip()
            if not line: continue
            try:
                tokens = shlex.split(line, posix=False)

            except ValueError as e:
                compilation_error("Invalid quoting or escape sequence", str(e), line, lineno, src_file)
                continue
            if not tokens: continue
            cmd = tokens[0]
            rule = INSTRUCTION_RULES.get(cmd, {"count": 0, "pattern": re.compile(r"^(_ cmt)$"), "syntax": f"{cmd} is unknown command"})
            lexeme_count = rule["count"]
            if cmd == "write" and len(tokens) > 1 and not tokens[1].startswith('"'):
                tokens[1] = '"' + tokens[1] + '"'
            parsed, pattern_str = [], ""
            for i in range(lexeme_count):
                if i >= len(tokens):
                    lex = None
                else:
                    lex = tokens[i]
                lex_type = parse_lexeme(lex)
                parsed.append(lex_type)
                pattern_str += lex_type[:5]
            # Collect constants for write
            if cmd == "write" and len(tokens) > 1:
                val_token = tokens[1]
                if val_token.startswith('"') and val_token.endswith('"'):
                    const = val_token
                elif val_token.startswith("label:"):
                    lbl = val_token[6:]
                    if lbl not in LABELS:
                        compilation_error("Label must be defined before use in write", "", line, lineno, src_file)
                        continue
                    const = f"LABEL:{lbl}"
                else:
                    const = val_token

    if const not in CONSTANTS:
        CONSTANTS.append(const)
        if const.startswith('"'):
            CONSTANTS_EVALUATED.append(const.strip('"'))
        elif const.startswith("LABEL:"):
            lbl = const[6:]
            idx = find_index(lbl, LABELS)
            CONSTANTS_EVALUATED.append(str(LABELS_ADDRESSES[idx]))
        elif const in SYMBOL_TABLE:
            CONSTANTS_EVALUATED.append(SYMBOL_TABLE[const])
        else:
            CONSTANTS_EVALUATED.append(const)

            pattern_str += "_ cmt"
            if not rule["pattern"].match(pattern_str):
                compilation_error(rule["syntax"], f"Unexpected arguments for command {cmd}", line, lineno, src_file)
                continue
            if cmd == "label":
                name = parsed[1][6:]
                if name in LABELS:
                    continue
                LABELS.append(name)
                LABELS_ADDRESSES.append(NEXT_INSTR_ADDRESS)
                continue
            if cmd == "var":
                name = parsed[1][6:]
                if name in VARIABLES:
                    continue
                VARIABLES.append(name)
                VARIABLES_DECL_ADDRESSES.append(NEXT_INSTR_ADDRESS)
                continue
            PARSED_LEXEMES.append(f"line {lineno}")
            PARSED_LEXEMES.extend(parsed)
            NEXT_INSTR_ADDRESS += 1

for c in CONSTANTS:
    CONSTANTS_ADDRESSES.append(NEXT_INSTR_ADDRESS)
    NEXT_INSTR_ADDRESS += 1
for v in VARIABLES:
    VARIABLES_ADDRESSES.append(NEXT_INSTR_ADDRESS)
    NEXT_INSTR_ADDRESS += 1

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
if os.path.exists(OUTPUT_FILE): os.remove(OUTPUT_FILE)

output, LEXEME_INDEX, CUR_INSTRUCTION_NO = [], -1, FIRST_INSTRUCTION_NO - 1

def get_next_lexeme():
    global LEXEME_INDEX
    LEXEME_INDEX += 1
    return PARSED_LEXEMES[LEXEME_INDEX] if LEXEME_INDEX < len(PARSED_LEXEMES) else None

def eval_lexeme(lex, pos):
    if lex is None:
        compilation_error(
            "Unexpected end of instruction",
            "Instruction is missing one or more arguments",
            line="", line_no=CUR_LINE_NO, filename=CUR_FILE
        )
        return "0"

    p, t, v = lex[0], lex[2:5], lex[6:]
    if p == "_": p = ""
    if t == "cmd": return {
        "copy": INSTR_COPY_FROM_TO_ADDRESS,
        "write": INSTR_COPY_FROM_TO_ADDRESS,
        "jump": INSTR_JUMP,
        "jump_if": INSTR_JUMP_IF,
        "jump_if_not": INSTR_JUMP_IF_NOT,
        "jump_err": INSTR_JUMP_ERR,
        "cpu_exec": INSTR_CPU_EXEC,
        "DEBUG_ON": "DEBUG_ON",
        "DEBUG_OFF": "DEBUG_OFF"
    }.get(v, "")
    if t == "kto": return ""
    if t == "num": return p + v
    if t in {"reg", "opr", "sys", "clr", "mod"}:
        if v not in SYMBOL_TABLE:
            compilation_error(f"Symbol {v} is unknown", "", "", CUR_LINE_NO, CUR_FILE)
            return "0"
    return SYMBOL_TABLE[v]

    if t == "str":
        quoted = f'"{v}"'
        return str(CONSTANTS_ADDRESSES[CONSTANTS.index(quoted)]) if quoted in CONSTANTS else quoted
    if t == "lbl":
        if pos == "write_1":
            return str(CONSTANTS_ADDRESSES[find_index(f"LABEL:{v}", CONSTANTS)])
        idx = find_index(v, LABELS)
        return str(LABELS_ADDRESSES[idx]) if idx != -1 else "0"
    if t == "var":
        idx = find_index(v, VARIABLES)
        if idx == -1:
            compilation_error("Variable should be declared before usage", f"Variable {v} is not defined", "", CUR_LINE_NO, CUR_FILE)
            return "0"
        if CUR_INSTRUCTION_NO < VARIABLES_DECL_ADDRESSES[idx]:
            compilation_error("Variable should be defined before use", f"Variable {v} used before declaration", "", CUR_LINE_NO, CUR_FILE)
            return "0"
        return f"{p}{VARIABLES_ADDRESSES[idx]}"

    return p + v

def debug_string(lex, pos):
    if lex is None:
        return "<missing>"
    p, t, v = lex[0], lex[2:5], lex[6:]
    return f'"{v}"' if t == "str" or (t == "num" and pos == "write_1") else f"{t}:{v}" if t in {"var", "lbl"} else (v if p == "_" else p + v)

CUR_FILE, CUR_LINE_NO = "", ""
while True:
    lexeme = get_next_lexeme()
    if not lexeme: break
    if lexeme.startswith("file "): CUR_FILE = lexeme[5:]; continue
    CUR_FILE = CUR_FILE or "<unknown>"
    CUR_LINE_NO = CUR_LINE_NO or 0
    if lexeme.startswith("line "): CUR_LINE_NO = lexeme[5:]; CUR_INSTRUCTION_NO += 1; continue
    cmd = lexeme[6:]
    count = 4 if cmd in ("write", "copy") else 2 if cmd.startswith("jump") else 1 if cmd in ("cpu_exec", "DEBUG_ON", "DEBUG_OFF") else 0
    instr, debug = [], ["#"]
    for i in range(count):
        lex = get_next_lexeme()
        if lex is None:
            compilation_error("Unexpected end of instruction", "Instruction is missing one or more arguments", line="", line_no=CUR_LINE_NO, filename=CUR_FILE)
            break
        instr.append(eval_lexeme(lex, f"{cmd}_{i}"))
        debug.append(debug_string(lex, f"{cmd}_{i}"))
    final = f"{' '.join(instr)} {' '.join(debug)}" if DEBUG_INFO else ' '.join(instr)
    output.append(final)

with open(OUTPUT_FILE, "w") as out:
    for line in output:
        if "#" in line:
            code, comment = line.split("#", 1)
            out.write(f"{code:<15} # {comment.strip()}\n")
        else:
            out.write(line + "\n")

for c in CONSTANTS:
    with open(OUTPUT_FILE, "a") as out: out.write(c.strip('"') + "\n")
for _ in VARIABLES:
    with open(OUTPUT_FILE, "a") as out: out.write("\n")

if COMPILATION_ERROR_COUNT:
    print(f"\033[91mCompilation failed: {COMPILATION_ERROR_COUNT} error(s).\033[0m")
    sys.exit(COMPILATION_ERROR_COUNT)
else:
    print(f"\033[92mCompilation succeeded. Output image: {OUTPUT_FILE}\033[0m")
if NEXT_INSTR_ADDRESS >= GLOBAL_RAM_SIZE:
    print(f"\033[93mNot enough RAM. RAM size: {GLOBAL_RAM_SIZE}, last used: {NEXT_INSTR_ADDRESS}\033[0m")
