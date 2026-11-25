"""Read dependencies from Cargo.toml text and rewrite them in place (keeping comments, features, layout)."""
import re, tomllib

DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*(#.*)?$")
_LINE = re.compile(r'^(\s*)([A-Za-z0-9_-]+)(\s*=\s*)(.*)$')


def extract(text):
    """Accept a Cargo.toml, a bare [dependencies] list, or an AI reply with a ```toml block."""
    m = re.search(r"```(?:toml)?\s*\n(.*?)```", text, re.S)
    text = m.group(1) if m else text
    if not re.search(r"^\s*\[", text, re.M):
        text = "[dependencies]\n" + text
    return text


def _is_dep_table(name):
    parts = name.strip().split(".")
    return parts[-1] in DEP_TABLES or (len(parts) >= 2 and parts[-2] in DEP_TABLES)


def dependencies(text):
    """-> [(crate, requirement)] from all dependency tables (incl. target-specific ones)."""
    data = tomllib.loads(text)
    tables = [data.get(t, {}) for t in DEP_TABLES]
    for spec in data.get("target", {}).values():
        tables += [spec.get(t, {}) for t in DEP_TABLES]
    out = []
    for table in tables:
        for name, spec in table.items():
            if isinstance(spec, str):
                out.append((name, spec))
            elif isinstance(spec, dict) and "path" not in spec and "git" not in spec:
                out.append((spec.get("package", name), spec.get("version", "*")))
    return out


def rewrite(text, fixes):
    """fixes: {crate: {'crate': new_name_or_None, 'req': new_req_or_None}}; new_name None = remove.
    Returns the new text. Handles `a = "1"`, `a = { version = "1", ... }` and [dependencies.a] tables."""
    out, section, sub = [], None, None
    for line in text.splitlines(keepends=True):
        sm = _SECTION.match(line)
        if sm:
            section = sm.group(1).strip()
            parts = section.split(".")
            sub = parts[-1] if len(parts) >= 2 and parts[-2] in DEP_TABLES else None
            if sub in fixes and fixes[sub]["crate"] and fixes[sub]["crate"] != sub:
                line = line.replace(f".{sub}]", f".{fixes[sub]['crate']}]")
            out.append(line)
            continue
        lm = _LINE.match(line)
        if section and lm:
            indent, key, eq, value = lm.groups()
            if sub and sub in fixes and key == "version" and fixes[sub]["req"]:
                line = f'{indent}version{eq}"{fixes[sub]["req"]}"' + ("\n" if line.endswith("\n") else "")
            elif _is_dep_table(section) and not sub and key in fixes:
                fx = fixes[key]
                if fx["crate"] is None:
                    line = f"# crateguard: removed, `{key}` does not exist on crates.io: {line.strip()}\n"
                else:
                    if fx["req"]:
                        if value.lstrip().startswith("{"):
                            if re.search(r'version\s*=\s*"[^"]*"', value):
                                value = re.sub(r'(version\s*=\s*)"[^"]*"', rf'\g<1>"{fx["req"]}"', value, count=1)
                            else:
                                value = value.replace("{", f'{{ version = "{fx["req"]}",', 1)
                        else:
                            value = re.sub(r'"[^"]*"', f'"{fx["req"]}"', value, count=1)
                    line = f"{indent}{fx['crate']}{eq}{value}" + ("\n" if line.endswith("\n") and not value.endswith("\n") else "")
        out.append(line)
    return "".join(out)
