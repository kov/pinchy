#!/usr/bin/env rust-script
//! In-place userspace event formatter migration helper.
//!
//! Converts legacy `event.data.*` arms in `handle_event()` to compact
//! payload decoding, but only for arms that are not migrated yet.
//!
//! Usage:
//!   rustc scripts/migrate-events-inplace.rs -O -o /tmp/migrate-events-inplace
//!   /tmp/migrate-events-inplace [--dry-run] pinchy/src/events.rs

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        return Err("usage: migrate-events-inplace [--dry-run] <pinchy/src/events.rs>".to_string());
    }

    let dry_run = if args.first().map(String::as_str) == Some("--dry-run") {
        args.remove(0);
        true
    } else {
        false
    };

    if args.len() != 1 {
        return Err("usage: migrate-events-inplace [--dry-run] <pinchy/src/events.rs>".to_string());
    }

    let events_path = PathBuf::from(&args[0]);

    if !events_path.exists() {
        return Err(format!("file does not exist: {}", events_path.display()));
    }

    let root = find_repo_root(&events_path)?;
    let common_lib = root.join("pinchy-common/src/lib.rs");

    let events_original = fs::read_to_string(&events_path)
        .map_err(|e| format!("failed reading {}: {e}", events_path.display()))?;
    let common_original = fs::read_to_string(&common_lib)
        .map_err(|e| format!("failed reading {}: {e}", common_lib.display()))?;

    let field_type_map = parse_union_field_type_map(&common_original)?;

    let (events_migrated, migrated_arms, migrated_bindings) =
        migrate_events_file(&events_original, &field_type_map)?;

    if migrated_arms.is_empty() {
        println!("no legacy arms found in {}", events_path.display());
        return Ok(());
    }

    println!(
        "migrated {} match arms ({} data bindings) in {}:",
        migrated_arms.len(),
        migrated_bindings,
        events_path.display()
    );

    for arm in &migrated_arms {
        println!("  - {arm}");
    }

    if dry_run {
        println!("dry-run: no files modified");
        return Ok(());
    }

    fs::write(&events_path, events_migrated)
        .map_err(|e| format!("failed writing {}: {e}", events_path.display()))?;

    println!("updated: {}", events_path.display());

    Ok(())
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
        if cursor.join("pinchy-common/src/lib.rs").exists() && cursor.join("pinchy/src/events.rs").exists() {
            return Ok(cursor);
        }

        let Some(parent) = cursor.parent() else {
            break;
        };

        cursor = parent.to_path_buf();
    }

    Err("could not locate repository root from events path".to_string())
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

fn migrate_events_file(
    file_text: &str,
    field_type_map: &HashMap<String, String>,
) -> Result<(String, Vec<String>, usize), String> {
    let match_anchor = "    match header.syscall_nr {";
    let match_start = file_text
        .find(match_anchor)
        .ok_or_else(|| "could not find `match header.syscall_nr` in handle_event()".to_string())?;

    let match_block_start = file_text[match_start..]
        .find('{')
        .ok_or_else(|| "could not find `{` for handle_event match".to_string())?
        + match_start;

    let match_block_end = find_matching_brace(file_text, match_block_start)?;

    let prefix = &file_text[..match_block_start + 1];
    let match_body = &file_text[match_block_start + 1..match_block_end];
    let suffix = &file_text[match_block_end..];

    let lines = match_body
        .lines()
        .map(|line| format!("{line}\n"))
        .collect::<Vec<_>>();

    let mut out_body = String::new();
    let mut migrated_arms = Vec::new();
    let mut migrated_bindings = 0usize;

    let mut i = 0usize;

    while i < lines.len() {
        let line = &lines[i];

        let Some((_indent, arm_label)) = parse_match_arm_header(line) else {
            out_body.push_str(line);
            i += 1;
            continue;
        };

        let mut brace_depth = count_braces(line);
        let mut j = i;

        while brace_depth > 0 {
            j += 1;

            if j >= lines.len() {
                return Err(format!("unterminated match arm near: {}", arm_label));
            }

            brace_depth += count_braces(&lines[j]);
        }

        let arm_text = lines[i..=j].concat();

        if !arm_text.contains("event.data.") {
            out_body.push_str(&arm_text);
            i = j + 1;
            continue;
        }

        let (updated_arm, binding_count) = rewrite_arm_event_data(&arm_text, field_type_map)?;

        out_body.push_str(&updated_arm);
        migrated_bindings += binding_count;
        migrated_arms.push(arm_label);

        i = j + 1;
    }

    let mut out = String::new();
    out.push_str(prefix);
    out.push_str(&out_body);
    out.push_str(suffix);

    Ok((out, migrated_arms, migrated_bindings))
}

fn rewrite_arm_event_data(
    arm_text: &str,
    field_type_map: &HashMap<String, String>,
) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut converted = 0usize;

    for line in arm_text.lines() {
        let mut emitted = false;

        if let Some((indent, var_name, field)) = parse_event_data_binding_line(line) {
            let Some(ty) = field_type_map.get(&field) else {
                return Err(format!(
                    "could not find type for union field `{field}` while migrating line: {line}"
                ));
            };

            out.push_str(&format!(
                "{indent}let {var_name} = unsafe {{ std::ptr::read_unaligned(payload.as_ptr() as *const pinchy_common::{ty}) }};\n"
            ));

            converted += 1;
            emitted = true;
        }

        if !emitted {
            let line = line
                .replace("event.return_value", "header.return_value")
                .replace("event.syscall_nr", "header.syscall_nr");
            out.push_str(&line);
            out.push('\n');
        }
    }

    Ok((out, converted))
}

fn parse_match_arm_header(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();

    if !trimmed.starts_with("syscalls::") {
        return None;
    }

    if !trimmed.contains("=>") || !trimmed.contains('{') {
        return None;
    }

    let indent_len = line.len().saturating_sub(trimmed.len());
    let indent = line[..indent_len].to_string();

    let label = trimmed
        .split("=>")
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string();

    Some((indent, label))
}

fn parse_event_data_binding_line(line: &str) -> Option<(String, String, String)> {
    let trimmed = line.trim();

    if !trimmed.starts_with("let ") || !trimmed.contains("event.data.") {
        return None;
    }

    let indent_len = line.len().saturating_sub(line.trim_start().len());
    let indent = line[..indent_len].to_string();

    let Some((lhs, rhs)) = trimmed.split_once('=') else {
        return None;
    };

    let var_name = lhs.strip_prefix("let ")?.trim().to_string();

    let marker = "event.data.";
    let start = rhs.find(marker)? + marker.len();
    let tail = &rhs[start..];

    let mut field = String::new();

    for ch in tail.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            field.push(ch);
        } else {
            break;
        }
    }

    if field.is_empty() {
        return None;
    }

    Some((indent, var_name, field))
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
