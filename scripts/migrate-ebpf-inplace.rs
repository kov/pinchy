#!/usr/bin/env rust-script
//! In-place eBPF compact migration helper.
//!
//! Usage:
//!   rustc scripts/migrate-ebpf-inplace.rs -O -o /tmp/migrate-ebpf-inplace
//!   /tmp/migrate-ebpf-inplace [--dry-run] <pinchy-ebpf/src/*.rs>

use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
struct ConvertedArm {
    syscall: String,
    ty: String,
    cfg_attr: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        return Err("usage: migrate-ebpf-inplace [--dry-run] <handler_file>".to_string());
    }

    let dry_run = if args.first().map(String::as_str) == Some("--dry-run") {
        args.remove(0);
        true
    } else {
        false
    };

    if args.len() != 1 {
        return Err("usage: migrate-ebpf-inplace [--dry-run] <handler_file>".to_string());
    }

    let handler_path = PathBuf::from(&args[0]);

    if !handler_path.exists() {
        return Err(format!("handler file does not exist: {}", handler_path.display()));
    }

    let root = find_repo_root(&handler_path)?;
    let common_lib = root.join("pinchy-common/src/lib.rs");

    let handler_original = fs::read_to_string(&handler_path)
        .map_err(|e| format!("failed reading {}: {e}", handler_path.display()))?;
    let common_original = fs::read_to_string(&common_lib)
        .map_err(|e| format!("failed reading {}: {e}", common_lib.display()))?;

    let field_type_map = parse_union_field_type_map(&common_original)?;

    let (handler_original, return_value_var) = match detect_return_value_var(&handler_original) {
        Some(var) => (handler_original, var),
        None => (
            insert_return_value_binding(&handler_original)?,
            "return_value".to_string(),
        ),
    };

    let (handler_migrated, converted, skipped) =
        migrate_handler_file(&handler_original, &field_type_map, &return_value_var)?;

    if converted.is_empty() {
        println!("no eligible legacy arms found in {}", handler_path.display());

        if !skipped.is_empty() {
            println!("skipped arms:");
            for item in skipped {
                println!("  - {item}");
            }
        }

        return Ok(());
    }

    let (handler_migrated, removed_entry_scaffolding) = cleanup_entry_scaffolding(&handler_migrated);

    let (common_migrated, inserted_payload_arms) = add_compact_payload_arms(&common_original, &converted)?;

    println!("converted {} syscall arms in {}:", converted.len(), handler_path.display());
    for arm in &converted {
        println!("  - {} -> {}", arm.syscall, arm.ty);
    }

    if !skipped.is_empty() {
        println!("skipped {} arms:", skipped.len());
        for item in &skipped {
            println!("  - {item}");
        }
    }

    if removed_entry_scaffolding {
        println!("removed legacy Entry scaffolding");
    }

    if inserted_payload_arms.is_empty() {
        println!("compact_payload_size(): no new arms were needed");
    } else {
        println!("compact_payload_size(): inserted {} new arms", inserted_payload_arms.len());
        for arm in &inserted_payload_arms {
            println!("  - {}", arm);
        }
    }

    if dry_run {
        println!("dry-run: no files modified");
        return Ok(());
    }

    fs::write(&handler_path, handler_migrated)
        .map_err(|e| format!("failed writing {}: {e}", handler_path.display()))?;
    fs::write(&common_lib, common_migrated)
        .map_err(|e| format!("failed writing {}: {e}", common_lib.display()))?;

    println!("updated: {}", handler_path.display());
    println!("updated: {}", common_lib.display());

    Ok(())
}

fn cleanup_entry_scaffolding(file_text: &str) -> (String, bool) {
    if file_text.contains("data_mut!(entry,") || file_text.contains("&mut entry.data.") {
        return (file_text.to_string(), false);
    }

    let mut changed = false;
    let mut out = Vec::new();

    for line in file_text.lines() {
        let trimmed = line.trim();

        if (trimmed.starts_with("let mut entry =") || trimmed.starts_with("let entry ="))
            && trimmed.contains("Entry::new(")
        {
            changed = true;
            continue;
        }

        if trimmed == "entry.submit();" || trimmed == "entry.discard();" {
            changed = true;
            continue;
        }

        let mut updated = line.to_string();

        if updated.contains("use crate::{") && updated.contains("data_mut") {
            let old = updated.clone();
            updated = updated.replace("data_mut, ", "");
            updated = updated.replace(", data_mut", "");
            updated = updated.replace("{data_mut}", "{}");

            if updated != old {
                changed = true;
            }
        }

        out.push(updated);
    }

    let mut text = out.join("\n");
    if file_text.ends_with('\n') {
        text.push('\n');
    }

    (text, changed)
}

fn find_repo_root(from: &Path) -> Result<PathBuf, String> {
    let mut cursor = from
        .canonicalize()
        .map_err(|e| format!("failed to resolve {}: {e}", from.display()))?;

    if cursor.is_file() {
        cursor = cursor
            .parent()
            .ok_or_else(|| format!("no parent for {}", from.display()))?
            .to_path_buf();
    }

    loop {
        if cursor.join("pinchy-common/src/lib.rs").exists() && cursor.join("pinchy-ebpf").exists() {
            return Ok(cursor);
        }

        let Some(parent) = cursor.parent() else {
            break;
        };

        cursor = parent.to_path_buf();
    }

    Err("could not locate repository root from handler path".to_string())
}

fn parse_union_field_type_map(common_lib: &str) -> Result<HashMap<String, String>, String> {
    let union_start = common_lib
        .find("pub union SyscallEventData")
        .ok_or_else(|| "could not find `pub union SyscallEventData`".to_string())?;

    let block_start = common_lib[union_start..]
        .find('{')
        .ok_or_else(|| "could not find `{` for SyscallEventData".to_string())?
        + union_start;

    let block_end = find_matching_brace(common_lib, block_start)?;

    let block = &common_lib[block_start + 1..block_end];
    let mut map = HashMap::new();

    for line in block.lines() {
        let trimmed = line.trim();

        if !trimmed.starts_with("pub ") {
            continue;
        }

        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };

        let Some((field, rhs)) = rest.split_once(':') else {
            continue;
        };

        let field = field.trim();
        let ty = rhs.trim().trim_end_matches(',').trim();

        if !field.is_empty() && ty.ends_with("Data") {
            map.insert(field.to_string(), ty.to_string());
        }
    }

    if map.is_empty() {
        return Err("failed to parse any SyscallEventData field/type entries".to_string());
    }

    Ok(map)
}

fn migrate_handler_file(
    file_text: &str,
    field_type_map: &HashMap<String, String>,
    return_value_var: &str,
) -> Result<(String, Vec<ConvertedArm>, Vec<String>), String> {
    let lines = file_text.lines().map(|line| format!("{line}\n")).collect::<Vec<_>>();

    let mut out = String::new();
    let mut converted = Vec::new();
    let mut skipped = Vec::new();

    let mut i = 0;

    while i < lines.len() {
        let line = &lines[i];

        let Some((indent, syscall)) = parse_syscall_arm_header(line) else {
            out.push_str(line);
            i += 1;
            continue;
        };

        let mut brace_depth = count_braces(line);
        let mut j = i;

        while brace_depth > 0 {
            j += 1;

            if j >= lines.len() {
                return Err(format!("unterminated match arm starting at line {}", i + 1));
            }

            brace_depth += count_braces(&lines[j]);
        }

        let arm_lines = &lines[i..=j];
        let arm_text = arm_lines.concat();

        if arm_text.contains("submit_compact_payload::<") {
            out.push_str(&arm_text);
            i = j + 1;
            continue;
        }

        let decl_idx = arm_lines
            .iter()
            .position(|line| line.contains("data_mut!(entry,"))
            .or_else(|| arm_lines.iter().position(|line| line.contains("&mut entry.data.")));

        let Some(decl_idx) = decl_idx else {
            out.push_str(&arm_text);
            i = j + 1;
            continue;
        };

        let field = parse_data_field(arm_lines[decl_idx].trim())
            .ok_or_else(|| format!("could not parse data field in arm {syscall} (line {})", i + decl_idx + 1))?;

        let Some(ty) = field_type_map.get(&field).cloned() else {
            skipped.push(format!("{syscall}: field `{field}` not found in SyscallEventData"));
            out.push_str(&arm_text);
            i = j + 1;
            continue;
        };

        let body_start = 1;
        let body_end_exclusive = arm_lines.len().saturating_sub(1);

        if decl_idx == 0 || decl_idx >= body_end_exclusive {
            skipped.push(format!("{syscall}: unsupported declaration position"));
            out.push_str(&arm_text);
            i = j + 1;
            continue;
        }

        let old_body_indent = format!("{indent}    ");
        let new_body_indent = format!("{indent}            ");

        let mut new_body = String::new();
        let mut unsupported = false;

        for (idx, body_line) in arm_lines[body_start..body_end_exclusive].iter().enumerate() {
            if idx + body_start == decl_idx {
                continue;
            }

            let mut line = body_line.clone();

            if line.trim_start().starts_with("let data =") {
                continue;
            }

            if line.contains("entry.") {
                unsupported = true;
                break;
            }

            line = line.replacen(&old_body_indent, &new_body_indent, 1);
            line = line.replace("data.", "payload.");

            new_body.push_str(&line);
        }

        if unsupported {
            skipped.push(format!("{syscall}: body references `entry.` after data binding"));
            out.push_str(&arm_text);
            i = j + 1;
            continue;
        }

        let mut cfg_attr = None;
        if i > 0 {
            let prev_trimmed = lines[i - 1].trim();
            if prev_trimmed.starts_with("#[cfg(") {
                cfg_attr = Some(prev_trimmed.to_string());
            }
        }

        let compact_arm = format!(
            "{indent}syscalls::{syscall} => {{\n{indent}    crate::util::submit_compact_payload::<pinchy_common::{ty}, _>(\n{indent}        &ctx,\n{indent}        syscalls::{syscall},\n{indent}        {return_value_var},\n{indent}        |payload| {{\n{new_body}{indent}        }},\n{indent}    )?;\n{indent}}}\n"
        );

        out.push_str(&compact_arm);
        converted.push(ConvertedArm {
            syscall,
            ty,
            cfg_attr,
        });

        i = j + 1;
    }

    Ok((out, converted, skipped))
}

fn detect_return_value_var(file_text: &str) -> Option<String> {
    for line in file_text.lines() {
        let trimmed = line.trim();

        if !trimmed.starts_with("let ") || !trimmed.contains("get_return_value(") {
            continue;
        }

        let after_let = trimmed.strip_prefix("let ")?;
        let var = after_let.split('=').next()?.trim();

        if !var.is_empty() {
            return Some(var.to_string());
        }
    }

    None
}

fn insert_return_value_binding(file_text: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut inserted = false;

    for line in file_text.lines() {
        out.push_str(line);
        out.push('\n');

        if !inserted && line.contains("let args = ") && line.contains("get_args(") {
            let indent_len = line.len().saturating_sub(line.trim_start().len());
            let indent = &line[..indent_len];
            out.push_str(indent);
            out.push_str("let return_value = util::get_return_value(&ctx)?;\n");
            inserted = true;
        }
    }

    if !inserted {
        return Err(
            "could not auto-insert return_value binding (no `let args = ...get_args(...)` line found)"
                .to_string(),
        );
    }

    Ok(out)
}

fn add_compact_payload_arms(
    common_lib: &str,
    converted: &[ConvertedArm],
) -> Result<(String, Vec<String>), String> {
    let fn_start = common_lib
        .find("pub fn compact_payload_size")
        .ok_or_else(|| "could not find compact_payload_size()".to_string())?;

    let fn_block_start = common_lib[fn_start..]
        .find('{')
        .ok_or_else(|| "could not find `{` for compact_payload_size()".to_string())?
        + fn_start;

    let fn_block_end = find_matching_brace(common_lib, fn_block_start)?;

    let fn_text = &common_lib[fn_start..=fn_block_end];

    let mut to_insert = Vec::new();
    let mut seen = BTreeSet::new();

    for arm in converted {
        if !seen.insert((arm.syscall.clone(), arm.ty.clone(), arm.cfg_attr.clone())) {
            continue;
        }

        let key = format!("syscalls::{} =>", arm.syscall);

        if fn_text.contains(&key) {
            continue;
        }

        let mut line = String::new();

        if let Some(cfg) = &arm.cfg_attr {
            line.push_str("        ");
            line.push_str(cfg);
            line.push('\n');
        }

        line.push_str("        ");
        line.push_str(&format!(
            "syscalls::{} => Some(core::mem::size_of::<{}>()),\n",
            arm.syscall, arm.ty
        ));

        to_insert.push(line);
    }

    if to_insert.is_empty() {
        return Ok((common_lib.to_string(), Vec::new()));
    }

    let insert_anchor = "        _ => None,";
    let Some(anchor_pos_rel) = fn_text.find(insert_anchor) else {
        return Err("could not find `_ => None,` in compact_payload_size()".to_string());
    };

    let anchor_pos_abs = fn_start + anchor_pos_rel;

    let mut new_common = String::new();
    new_common.push_str(&common_lib[..anchor_pos_abs]);

    for line in &to_insert {
        new_common.push_str(line);
    }

    new_common.push_str(&common_lib[anchor_pos_abs..]);

    let inserted_names = to_insert
        .iter()
        .filter_map(|line| {
            line.lines()
                .find(|l| l.contains("syscalls::SYS_"))
                .map(|l| l.trim().to_string())
        })
        .collect::<Vec<_>>();

    Ok((new_common, inserted_names))
}

fn find_matching_brace(text: &str, open_idx: usize) -> Result<usize, String> {
    let mut depth: i32 = 0;

    for (offset, ch) in text[open_idx..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(open_idx + offset);
                }
            }
            _ => {}
        }
    }

    Err("could not find matching closing brace".to_string())
}

fn parse_syscall_arm_header(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();

    if !trimmed.starts_with("syscalls::SYS_") || !trimmed.contains("=>") || !trimmed.contains('{') {
        return None;
    }

    let indent_len = line.len().saturating_sub(trimmed.len());
    let indent = line[..indent_len].to_string();

    let after_prefix = trimmed.strip_prefix("syscalls::")?;
    let syscall = after_prefix
        .split_whitespace()
        .next()?
        .trim_end_matches('{')
        .trim_end_matches("=>")
        .trim()
        .to_string();

    if !syscall.starts_with("SYS_") {
        return None;
    }

    Some((indent, syscall))
}

fn parse_data_field(decl_line: &str) -> Option<String> {
    if let Some(start) = decl_line.find("data_mut!(entry,") {
        let tail = &decl_line[start + "data_mut!(entry,".len()..];
        let field = tail
            .split(')')
            .next()?
            .trim()
            .trim_end_matches(';')
            .to_string();
        if !field.is_empty() {
            return Some(field);
        }
    }

    if let Some(start) = decl_line.find("&mut entry.data.") {
        let tail = &decl_line[start + "&mut entry.data.".len()..];
        let mut field = String::new();

        for ch in tail.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                field.push(ch);
            } else {
                break;
            }
        }

        if !field.is_empty() {
            return Some(field);
        }
    }

    None
}

fn count_braces(line: &str) -> i32 {
    let mut n = 0;

    for ch in line.chars() {
        if ch == '{' {
            n += 1;
        }

        if ch == '}' {
            n -= 1;
        }
    }

    n
}
