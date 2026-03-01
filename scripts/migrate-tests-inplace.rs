#!/usr/bin/env rust-script
//! In-place test migration helper.
//!
//! Converts legacy `syscall_test!` blocks that construct `SyscallEvent { ... }`
//! into `syscall_compact_test!` blocks using `crate::tests::make_compact_test_data`.
//!
//! Usage:
//!   rustc scripts/migrate-tests-inplace.rs -O -o /tmp/migrate-tests-inplace
//!   /tmp/migrate-tests-inplace [--dry-run] <file_or_dir> [file_or_dir...]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct FileStats {
    converted_macros: usize,
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
        return Err("usage: migrate-tests-inplace [--dry-run] <file_or_dir> [file_or_dir...]".to_string());
    }

    let dry_run = if args.first().map(String::as_str) == Some("--dry-run") {
        args.remove(0);
        true
    } else {
        false
    };

    if args.is_empty() {
        return Err("usage: migrate-tests-inplace [--dry-run] <file_or_dir> [file_or_dir...]".to_string());
    }

    let mut files = Vec::new();

    for arg in &args {
        let path = PathBuf::from(arg);

        if path.is_dir() {
            collect_rs_files(&path, &mut files)?;
        } else if path.is_file() {
            files.push(path);
        } else {
            return Err(format!("path does not exist: {arg}"));
        }
    }

    files.sort();
    files.dedup();

    let mut total = 0usize;

    for file in files {
        let input = fs::read_to_string(&file)
            .map_err(|e| format!("failed reading {}: {e}", file.display()))?;

        let (output, stats) = migrate_file(&input)?;

        if stats.converted_macros == 0 {
            continue;
        }

        total += stats.converted_macros;

        if dry_run {
            println!(
                "{}: would convert {} syscall_test! blocks",
                file.display(),
                stats.converted_macros
            );
        } else {
            fs::write(&file, output)
                .map_err(|e| format!("failed writing {}: {e}", file.display()))?;
            println!(
                "{}: converted {} syscall_test! blocks",
                file.display(),
                stats.converted_macros
            );
        }
    }

    if dry_run {
        println!("dry-run: total blocks to convert: {total}");
    } else {
        println!("total converted blocks: {total}");
    }

    Ok(())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("failed to read dir {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read dir entry: {e}"))?;
        let path = entry.path();

        if path.is_dir() {
            collect_rs_files(&path, out)?;
            continue;
        }

        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }

    Ok(())
}

fn migrate_file(input: &str) -> Result<(String, FileStats), String> {
    let mut output = String::new();
    let mut stats = FileStats::default();

    let mut cursor = 0usize;

    while let Some(pos_rel) = input[cursor..].find("syscall_test!") {
        let pos = cursor + pos_rel;
        output.push_str(&input[cursor..pos]);

        let bang_end = pos + "syscall_test!".len();
        let rest = &input[bang_end..];

        let ws_len = rest.chars().take_while(|c| c.is_whitespace()).map(char::len_utf8).sum::<usize>();
        let paren_idx = bang_end + ws_len;

        if input[paren_idx..].chars().next() != Some('(') {
            output.push_str("syscall_test!");
            cursor = bang_end;
            continue;
        }

        let paren_end = find_matching_delim(input, paren_idx, '(', ')')?;
        let after_paren = &input[paren_end + 1..];
        let semi_len = after_paren
            .chars()
            .take_while(|c| c.is_whitespace())
            .map(char::len_utf8)
            .sum::<usize>();
        let semi_idx = paren_end + 1 + semi_len;

        if input[semi_idx..].chars().next() != Some(';') {
            return Err("expected `;` after syscall_test!(...)".to_string());
        }

        let full_end = semi_idx + 1;
        let macro_body = &input[paren_idx + 1..paren_end];

        let converted = try_convert_macro_body(macro_body)?;

        if let Some(new_body) = converted {
            output.push_str("syscall_compact_test!(");
            output.push_str(&new_body);
            output.push_str(");");
            stats.converted_macros += 1;
        } else {
            output.push_str(&input[pos..full_end]);
        }

        cursor = full_end;
    }

    output.push_str(&input[cursor..]);

    Ok((output, stats))
}

fn try_convert_macro_body(body: &str) -> Result<Option<String>, String> {
    let args = split_top_level_args(body)?;

    if args.len() != 3 {
        return Ok(None);
    }

    let name_arg = args[0].trim();
    let init_arg = args[1].trim();
    let expected_arg = args[2].trim();

    if !init_arg.starts_with('{') || !init_arg.ends_with('}') {
        return Ok(None);
    }

    let init_open = 0usize;
    let init_close = init_arg.len() - 1;
    let inner = &init_arg[init_open + 1..init_close];

    let Some(event_pos) = inner.find("SyscallEvent {") else {
        return Ok(None);
    };

    let event_open = event_pos + "SyscallEvent ".len();
    let event_close = find_matching_delim(inner, event_open, '{', '}')?;

    let prefix = inner[..event_pos].trim_end_matches(|c: char| c.is_whitespace());
    let suffix = inner[event_close + 1..].trim();

    if !suffix.is_empty() {
        return Ok(None);
    }

    let event_body = &inner[event_open + 1..event_close];
    let fields = parse_struct_fields(event_body)?;

    let Some(syscall_nr) = find_field_expr(&fields, "syscall_nr").map(str::trim) else {
        return Ok(None);
    };
    let Some(tid) = find_field_expr(&fields, "tid").map(str::trim) else {
        return Ok(None);
    };
    let Some(return_value) = find_field_expr(&fields, "return_value").map(str::trim) else {
        return Ok(None);
    };
    let Some(data_expr) = find_field_expr(&fields, "data").map(str::trim) else {
        return Ok(None);
    };

    let Ok((payload_expr, indent)) = extract_payload_expr_and_indent(inner, event_pos, data_expr)
    else {
        return Ok(None);
    };

    let mut new_init_inner = String::new();

    if !prefix.is_empty() {
        new_init_inner.push_str(prefix);
        new_init_inner.push('\n');
        new_init_inner.push('\n');
    }

    new_init_inner.push_str(&indent);
    new_init_inner.push_str("let data = ");
    new_init_inner.push_str(payload_expr.trim());
    new_init_inner.push_str(";\n\n");

    new_init_inner.push_str(&indent);
    new_init_inner.push_str("crate::tests::make_compact_test_data(");
    new_init_inner.push_str(syscall_nr);
    new_init_inner.push_str(", ");
    new_init_inner.push_str(tid);
    new_init_inner.push_str(", ");
    new_init_inner.push_str(return_value);
    new_init_inner.push_str(", &data)");

    let mut new_init = String::new();
    new_init.push('{');

    if !new_init_inner.is_empty() {
        new_init.push('\n');
        new_init.push_str(&new_init_inner);
        new_init.push('\n');
    }

    let closing_indent = detect_closing_indent(init_arg);
    new_init.push_str(&closing_indent);
    new_init.push('}');

    let rebuilt = format!(
        "\n    {name_arg},\n    {new_init},\n    {expected_arg}\n"
    );

    Ok(Some(rebuilt))
}

fn split_top_level_args(body: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut start = 0usize;

    let mut paren = 0i32;
    let mut brace = 0i32;
    let mut bracket = 0i32;

    let bytes = body.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;

        if c == '/' {
            if let Some(end) = try_skip_line_comment(body, i) {
                i = end + 1;
                continue;
            }

            if let Some(end) = try_skip_block_comment(body, i)? {
                i = end + 1;
                continue;
            }
        }

        if c == '"' {
            i = skip_string(body, i)?;
            i += 1;
            continue;
        }

        if c == '\'' {
            i = skip_char_lit(body, i)?;
            i += 1;
            continue;
        }

        if c == 'r' {
            if let Some(end) = try_skip_raw_string(body, i)? {
                i = end + 1;
                continue;
            }
        }

        match c {
            '(' => paren += 1,
            ')' => paren -= 1,
            '{' => brace += 1,
            '}' => brace -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            ',' if paren == 0 && brace == 0 && bracket == 0 => {
                args.push(body[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }

        i += 1;
    }

    args.push(body[start..].to_string());

    Ok(args)
}

fn parse_struct_fields(body: &str) -> Result<Vec<(String, String)>, String> {
    let parts = split_top_level_args(body)?;
    let mut fields = Vec::new();

    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some((name, expr)) = split_top_level_colon(trimmed)? else {
            continue;
        };

        fields.push((name.trim().to_string(), expr.trim().trim_end_matches(',').trim().to_string()));
    }

    Ok(fields)
}

fn split_top_level_colon(s: &str) -> Result<Option<(String, String)>, String> {
    let mut paren = 0i32;
    let mut brace = 0i32;
    let mut bracket = 0i32;

    let bytes = s.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;

        if c == '/' {
            if let Some(end) = try_skip_line_comment(s, i) {
                i = end + 1;
                continue;
            }

            if let Some(end) = try_skip_block_comment(s, i)? {
                i = end + 1;
                continue;
            }
        }

        if c == '"' {
            i = skip_string(s, i)?;
            i += 1;
            continue;
        }

        if c == '\'' {
            i = skip_char_lit(s, i)?;
            i += 1;
            continue;
        }

        if c == 'r' {
            if let Some(end) = try_skip_raw_string(s, i)? {
                i = end + 1;
                continue;
            }
        }

        match c {
            '(' => paren += 1,
            ')' => paren -= 1,
            '{' => brace += 1,
            '}' => brace -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            ':' if paren == 0 && brace == 0 && bracket == 0 => {
                return Ok(Some((s[..i].to_string(), s[i + 1..].to_string())));
            }
            _ => {}
        }

        i += 1;
    }

    Ok(None)
}

fn find_field_expr<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, expr)| expr.as_str())
}

fn extract_payload_expr_and_indent(
    init_inner: &str,
    event_pos: usize,
    data_expr: &str,
) -> Result<(String, String), String> {
    let data_open = data_expr
        .find('{')
        .ok_or_else(|| "data field expression does not contain `{`".to_string())?;
    let data_close = find_matching_delim(data_expr, data_open, '{', '}')?;

    let data_struct_body = &data_expr[data_open + 1..data_close];
    let data_fields = parse_struct_fields(data_struct_body)?;

    if data_fields.len() != 1 {
        return Err("expected exactly one field in SyscallEventData initializer".to_string());
    }

    let payload_expr = data_fields[0].1.clone();

    let indent = detect_indent_before(init_inner, event_pos);

    Ok((payload_expr, indent))
}

fn detect_indent_before(s: &str, pos: usize) -> String {
    let line_start = s[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    s[line_start..pos]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect()
}

fn detect_closing_indent(init_arg: &str) -> String {
    let without_last = &init_arg[..init_arg.len().saturating_sub(1)];
    let line_start = without_last.rfind('\n').map(|i| i + 1).unwrap_or(0);
    without_last[line_start..]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect()
}

fn find_matching_delim(s: &str, open_idx: usize, open: char, close: char) -> Result<usize, String> {
    let bytes = s.as_bytes();

    if bytes.get(open_idx).copied().map(|b| b as char) != Some(open) {
        return Err("find_matching_delim: open index does not point to open delimiter".to_string());
    }

    let mut depth = 0i32;
    let mut i = open_idx;

    while i < bytes.len() {
        let c = bytes[i] as char;

        if c == '/' {
            if let Some(end) = try_skip_line_comment(s, i) {
                i = end + 1;
                continue;
            }

            if let Some(end) = try_skip_block_comment(s, i)? {
                i = end + 1;
                continue;
            }
        }

        if c == '"' {
            i = skip_string(s, i)?;
            i += 1;
            continue;
        }

        if c == '\'' {
            i = skip_char_lit(s, i)?;
            i += 1;
            continue;
        }

        if c == 'r' {
            if let Some(end) = try_skip_raw_string(s, i)? {
                i = end + 1;
                continue;
            }
        }

        if c == open {
            depth += 1;
        }

        if c == close {
            depth -= 1;

            if depth == 0 {
                return Ok(i);
            }
        }

        i += 1;
    }

    Err("could not find matching delimiter".to_string())
}

fn skip_string(s: &str, start: usize) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] as char {
            '\\' => i += 2,
            '"' => return Ok(i),
            _ => i += 1,
        }
    }

    Err("unterminated string literal".to_string())
}

fn skip_char_lit(s: &str, start: usize) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut i = start + 1;

    while i < bytes.len() {
        match bytes[i] as char {
            '\\' => i += 2,
            '\'' => return Ok(i),
            _ => i += 1,
        }
    }

    Err("unterminated char literal".to_string())
}

fn try_skip_raw_string(s: &str, start: usize) -> Result<Option<usize>, String> {
    let bytes = s.as_bytes();

    if bytes.get(start).copied().map(|b| b as char) != Some('r') {
        return Ok(None);
    }

    let mut i = start + 1;
    let mut hashes = 0usize;

    while i < bytes.len() && bytes[i] as char == '#' {
        hashes += 1;
        i += 1;
    }

    if i >= bytes.len() || bytes[i] as char != '"' {
        return Ok(None);
    }

    i += 1;

    loop {
        if i >= bytes.len() {
            return Err("unterminated raw string literal".to_string());
        }

        if bytes[i] as char == '"' {
            let mut j = i + 1;
            let mut matched = 0usize;

            while matched < hashes && j < bytes.len() && bytes[j] as char == '#' {
                matched += 1;
                j += 1;
            }

            if matched == hashes {
                return Ok(Some(j - 1));
            }
        }

        i += 1;
    }
}

fn try_skip_line_comment(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();

    if bytes.get(start).copied() != Some(b'/') || bytes.get(start + 1).copied() != Some(b'/') {
        return None;
    }

    let mut i = start + 2;

    while i < bytes.len() {
        if bytes[i] == b'\n' {
            return Some(i);
        }

        i += 1;
    }

    Some(bytes.len().saturating_sub(1))
}

fn try_skip_block_comment(s: &str, start: usize) -> Result<Option<usize>, String> {
    let bytes = s.as_bytes();

    if bytes.get(start).copied() != Some(b'/') || bytes.get(start + 1).copied() != Some(b'*') {
        return Ok(None);
    }

    let mut i = start + 2;
    let mut depth = 1i32;

    while i + 1 < bytes.len() {
        if bytes[i] == b'/' && bytes[i + 1] == b'*' {
            depth += 1;
            i += 2;
            continue;
        }

        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            depth -= 1;
            i += 2;

            if depth == 0 {
                return Ok(Some(i.saturating_sub(1)));
            }

            continue;
        }

        i += 1;
    }

    Err("unterminated block comment".to_string())
}
