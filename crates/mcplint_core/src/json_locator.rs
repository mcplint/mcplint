//! JSON location tracker — maps RFC 6901 JSON Pointers to source regions.
//!
//! Parses JSON content character-by-character to build a mapping from
//! JSON Pointer (e.g., "/mcpServers/filesystem") to a source Region
//! with precise line/column numbers.
//!
//! This is used to provide accurate evidence locations for findings,
//! enabling exact line-level annotations in SARIF output and CLI display.

use serde_json::Value;
use std::collections::HashMap;

/// A region in a source file, with 1-based line and column numbers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Region {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

/// Maps JSON Pointers to their source regions.
#[derive(Debug, Clone)]
pub struct JsonLocationMap {
    /// Pointer string → Region in source.
    locations: HashMap<String, Region>,
}

impl JsonLocationMap {
    /// Build a location map from raw JSON source text.
    ///
    /// Parses the JSON twice:
    /// 1. Structured parse via serde_json to get the value tree
    /// 2. Character scan to find byte offsets of keys and values
    ///
    /// If the JSON is malformed, returns an empty map (never fails).
    pub fn from_source(source: &str) -> Self {
        let parsed = match serde_json::from_str::<Value>(source) {
            Ok(v) => v,
            Err(_) => {
                return Self {
                    locations: HashMap::new(),
                }
            }
        };

        let line_index = LineIndex::new(source);
        let mut locations = HashMap::new();

        // Build the mapping by walking the value tree and finding each
        // key/value in the source text.
        Self::walk_value(source, &parsed, "", &line_index, &mut locations);

        Self { locations }
    }

    /// Look up the region for a JSON Pointer.
    pub fn get(&self, pointer: &str) -> Option<&Region> {
        self.locations.get(pointer)
    }

    /// Return all mappings (for debugging/testing).
    pub fn entries(&self) -> &HashMap<String, Region> {
        &self.locations
    }

    /// Walk a JSON value tree, finding source positions for each node.
    fn walk_value(
        source: &str,
        value: &Value,
        pointer: &str,
        line_index: &LineIndex,
        locations: &mut HashMap<String, Region>,
    ) {
        match value {
            Value::Object(map) => {
                // Find the object's opening brace
                if let Some(region) = Self::find_value_region(source, value, pointer, line_index) {
                    locations.insert(pointer.to_string(), region);
                }

                for (key, child) in map {
                    let child_pointer = format!("{}/{}", pointer, escape_pointer(key));
                    Self::walk_value(source, child, &child_pointer, line_index, locations);
                }
            }
            Value::Array(arr) => {
                if let Some(region) = Self::find_value_region(source, value, pointer, line_index) {
                    locations.insert(pointer.to_string(), region);
                }

                for (i, child) in arr.iter().enumerate() {
                    let child_pointer = format!("{}/{}", pointer, i);
                    Self::walk_value(source, child, &child_pointer, line_index, locations);
                }
            }
            _ => {
                // Scalar value
                if let Some(region) = Self::find_value_region(source, value, pointer, line_index) {
                    locations.insert(pointer.to_string(), region);
                }
            }
        }
    }

    /// Find the source region of a value identified by its JSON pointer.
    ///
    /// Strategy: navigate the raw source text following the pointer segments,
    /// skipping through objects/arrays to find the target key/index, then
    /// determine the region of its value.
    fn find_value_region(
        source: &str,
        _value: &Value,
        pointer: &str,
        line_index: &LineIndex,
    ) -> Option<Region> {
        if pointer.is_empty() {
            // Root value — find the first non-whitespace char
            let start = skip_whitespace(source, 0)?;
            let end = find_value_end(source, start)?;
            return Some(line_index.region(start, end));
        }

        // Navigate through the source following the pointer segments
        let segments: Vec<&str> = pointer[1..].split('/').collect();
        let mut pos = skip_whitespace(source, 0)?;

        for segment in &segments {
            let ch = source.as_bytes().get(pos)?;

            match ch {
                b'{' => {
                    // Navigate into an object to find key `segment`
                    let key = unescape_pointer(segment);
                    pos = find_key_value_start(source, pos, &key)?;
                }
                b'[' => {
                    // Navigate into an array to find index `segment`
                    let index: usize = segment.parse().ok()?;
                    pos = find_array_element_start(source, pos, index)?;
                }
                _ => return None,
            }
        }

        let end = find_value_end(source, pos)?;
        Some(line_index.region(pos, end))
    }
}

/// Pre-computed line start offsets for O(1) byte-offset → line/column conversion.
struct LineIndex {
    /// Byte offset of the start of each line (0-indexed).
    line_starts: Vec<usize>,
}

impl LineIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, ch) in source.bytes().enumerate() {
            if ch == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    /// Convert a byte offset range to a 1-based Region.
    fn region(&self, start: usize, end: usize) -> Region {
        let (start_line, start_col) = self.line_col(start);
        let (end_line, end_col) = self.line_col(if end > 0 { end - 1 } else { 0 });
        Region {
            start_line,
            start_column: start_col,
            end_line,
            end_column: end_col,
        }
    }

    /// Convert a byte offset to 1-based (line, column).
    fn line_col(&self, offset: usize) -> (u32, u32) {
        let line = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let col = offset - self.line_starts[line];
        ((line + 1) as u32, (col + 1) as u32)
    }
}

// ── JSON navigation helpers ──

/// Skip whitespace starting at `pos`, return offset of next non-whitespace.
fn skip_whitespace(source: &str, mut pos: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    while pos < bytes.len() {
        match bytes[pos] {
            b' ' | b'\t' | b'\n' | b'\r' => pos += 1,
            _ => return Some(pos),
        }
    }
    None
}

/// Find the byte offset where the value for `key` starts within an object at `pos`.
/// `pos` must point to the opening `{`.
fn find_key_value_start(source: &str, pos: usize, key: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut p = pos + 1; // skip '{'

    loop {
        p = skip_whitespace(source, p)?;
        if bytes.get(p)? == &b'}' {
            return None; // key not found
        }
        if bytes.get(p)? == &b',' {
            p += 1;
            continue;
        }

        // Expect a string key
        if bytes.get(p)? != &b'"' {
            return None;
        }

        let key_start = p;
        let parsed_key = read_json_string(source, &mut p)?;

        // Skip whitespace and colon
        p = skip_whitespace(source, p)?;
        if bytes.get(p)? != &b':' {
            return None;
        }
        p += 1;
        p = skip_whitespace(source, p)?;

        if parsed_key == key {
            return Some(p);
        }

        // Skip the value to continue searching
        p = find_value_end(source, p)?;
        let _ = key_start; // suppress unused warning
    }
}

/// Find the byte offset where array element `index` starts.
/// `pos` must point to the opening `[`.
fn find_array_element_start(source: &str, pos: usize, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut p = pos + 1; // skip '['
    let mut current_index = 0;

    loop {
        p = skip_whitespace(source, p)?;
        if bytes.get(p)? == &b']' {
            return None; // index out of bounds
        }
        if bytes.get(p)? == &b',' {
            p += 1;
            continue;
        }

        if current_index == index {
            return Some(p);
        }

        // Skip this element's value
        p = find_value_end(source, p)?;
        current_index += 1;
    }
}

/// Find the byte offset just past the end of the JSON value starting at `pos`.
fn find_value_end(source: &str, pos: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let ch = *bytes.get(pos)?;

    match ch {
        b'"' => {
            // String: scan to closing quote
            let mut p = pos + 1;
            while p < bytes.len() {
                match bytes[p] {
                    b'\\' => p += 2, // skip escaped char
                    b'"' => return Some(p + 1),
                    _ => p += 1,
                }
            }
            None
        }
        b'{' => {
            // Object: find matching closing brace
            skip_matched(source, pos, b'{', b'}')
        }
        b'[' => {
            // Array: find matching closing bracket
            skip_matched(source, pos, b'[', b']')
        }
        b't' => Some(pos + 4), // true
        b'f' => Some(pos + 5), // false
        b'n' => Some(pos + 4), // null
        b'-' | b'0'..=b'9' => {
            // Number
            let mut p = pos + 1;
            while p < bytes.len() {
                match bytes[p] {
                    b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-' => p += 1,
                    _ => return Some(p),
                }
            }
            Some(p)
        }
        _ => None,
    }
}

/// Skip a matched pair of delimiters (handles nesting and strings).
fn skip_matched(source: &str, pos: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0;
    let mut p = pos;
    let mut in_string = false;

    while p < bytes.len() {
        match bytes[p] {
            b'\\' if in_string => {
                p += 2;
                continue;
            }
            b'"' => in_string = !in_string,
            c if c == open && !in_string => depth += 1,
            c if c == close && !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(p + 1);
                }
            }
            _ => {}
        }
        p += 1;
    }
    None
}

/// Read a JSON string starting at `pos` (which must be `"`).
/// Advances `pos` past the closing quote. Returns the unescaped string content.
fn read_json_string(source: &str, pos: &mut usize) -> Option<String> {
    let bytes = source.as_bytes();
    if bytes.get(*pos)? != &b'"' {
        return None;
    }
    *pos += 1;

    let mut result = String::new();
    while *pos < bytes.len() {
        match bytes[*pos] {
            b'\\' => {
                *pos += 1;
                match bytes.get(*pos)? {
                    b'"' => result.push('"'),
                    b'\\' => result.push('\\'),
                    b'/' => result.push('/'),
                    b'n' => result.push('\n'),
                    b'r' => result.push('\r'),
                    b't' => result.push('\t'),
                    _ => result.push(bytes[*pos] as char),
                }
                *pos += 1;
            }
            b'"' => {
                *pos += 1;
                return Some(result);
            }
            c => {
                result.push(c as char);
                *pos += 1;
            }
        }
    }
    None
}

/// Escape a key for use in a JSON Pointer (RFC 6901).
/// '~' → '~0', '/' → '~1'
pub fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Unescape a JSON Pointer segment.
fn unescape_pointer(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_single_line() {
        let idx = LineIndex::new(r#"{"a": 1}"#);
        assert_eq!(idx.line_col(0), (1, 1)); // {
        assert_eq!(idx.line_col(1), (1, 2)); // "
        assert_eq!(idx.line_col(6), (1, 7)); // 1
    }

    #[test]
    fn line_index_multi_line() {
        let source = "{\n  \"a\": 1\n}";
        let idx = LineIndex::new(source);
        assert_eq!(idx.line_col(0), (1, 1)); // {
        assert_eq!(idx.line_col(2), (2, 1)); // first space on line 2
        assert_eq!(idx.line_col(4), (2, 3)); // "
        assert_eq!(idx.line_col(11), (3, 1)); // }
    }

    #[test]
    fn locator_root_object() {
        let source = r#"{"key": "value"}"#;
        let map = JsonLocationMap::from_source(source);
        let root = map.get("").unwrap();
        assert_eq!(root.start_line, 1);
        assert_eq!(root.start_column, 1);
    }

    #[test]
    fn locator_simple_key() {
        let source = "{\n  \"name\": \"hello\"\n}";
        let map = JsonLocationMap::from_source(source);
        let region = map.get("/name").unwrap();
        // "hello" starts at line 2
        assert_eq!(region.start_line, 2);
    }

    #[test]
    fn locator_nested_object() {
        let source = r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx"
    }
  }
}"#;
        let map = JsonLocationMap::from_source(source);

        let servers = map.get("/mcpServers").unwrap();
        assert_eq!(servers.start_line, 2);

        let fs = map.get("/mcpServers/filesystem").unwrap();
        assert_eq!(fs.start_line, 3);

        let cmd = map.get("/mcpServers/filesystem/command").unwrap();
        assert_eq!(cmd.start_line, 4);
    }

    #[test]
    fn locator_array_elements() {
        let source = r#"{
  "tools": [
    {
      "name": "read_file"
    },
    {
      "name": "write_file"
    }
  ]
}"#;
        let map = JsonLocationMap::from_source(source);

        let tools = map.get("/tools").unwrap();
        assert_eq!(tools.start_line, 2);

        let t0 = map.get("/tools/0").unwrap();
        assert_eq!(t0.start_line, 3);

        let t1 = map.get("/tools/1").unwrap();
        assert_eq!(t1.start_line, 6);

        let t0_name = map.get("/tools/0/name").unwrap();
        assert_eq!(t0_name.start_line, 4);
    }

    #[test]
    fn locator_claude_desktop_style() {
        let source = r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"]
    }
  }
}"#;
        let map = JsonLocationMap::from_source(source);

        let fs = map.get("/mcpServers/filesystem").unwrap();
        assert_eq!(fs.start_line, 3);

        let pg = map.get("/mcpServers/postgres").unwrap();
        assert_eq!(pg.start_line, 7);

        let fs_args = map.get("/mcpServers/filesystem/args").unwrap();
        assert_eq!(fs_args.start_line, 5);
    }

    #[test]
    fn locator_malformed_json_returns_empty() {
        let map = JsonLocationMap::from_source("not json at all {{{");
        assert!(map.entries().is_empty());
    }

    #[test]
    fn locator_escaped_key() {
        let source = r#"{"a/b": 1, "c~d": 2}"#;
        let map = JsonLocationMap::from_source(source);
        // RFC 6901: / → ~1, ~ → ~0
        assert!(map.get("/a~1b").is_some());
        assert!(map.get("/c~0d").is_some());
    }

    #[test]
    fn locator_string_with_braces() {
        let source = r#"{"key": "value with { and } inside"}"#;
        let map = JsonLocationMap::from_source(source);
        let region = map.get("/key").unwrap();
        assert_eq!(region.start_line, 1);
    }

    #[test]
    fn region_end_columns() {
        let source = r#"{
  "name": "hello"
}"#;
        let map = JsonLocationMap::from_source(source);
        let region = map.get("/name").unwrap();
        assert_eq!(region.start_line, 2);
        assert_eq!(region.end_line, 2);
        // "hello" spans columns 11-17 (with quotes)
        assert!(region.end_column >= region.start_column);
    }

    #[test]
    fn locator_real_fixture_claude_desktop() {
        // Test against the actual unsafe Claude Desktop fixture.
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/claude_desktop/unsafe/claude_desktop_config.json");
        let content = std::fs::read_to_string(&fixture_path).expect("fixture exists");
        let map = JsonLocationMap::from_source(&content);

        // Verify key pointers resolve to correct lines
        let fs = map.get("/mcpServers/filesystem").unwrap();
        assert_eq!(fs.start_line, 3, "filesystem server starts on line 3");

        let shell = map.get("/mcpServers/shell").unwrap();
        assert_eq!(shell.start_line, 7, "shell server starts on line 7");

        let pg = map.get("/mcpServers/postgres").unwrap();
        assert_eq!(pg.start_line, 11, "postgres server starts on line 11");

        let fetch = map.get("/mcpServers/fetch").unwrap();
        assert_eq!(fetch.start_line, 19, "fetch server starts on line 19");

        // Verify nested env values
        let db_pass = map.get("/mcpServers/postgres/env/DB_PASSWORD").unwrap();
        assert_eq!(db_pass.start_line, 16, "DB_PASSWORD on line 16");
    }

    #[test]
    fn escape_pointer_no_special_chars() {
        assert_eq!(escape_pointer("simple"), "simple");
        assert_eq!(escape_pointer("my-server"), "my-server");
        assert_eq!(escape_pointer(""), "");
    }

    #[test]
    fn escape_pointer_tilde() {
        assert_eq!(escape_pointer("a~b"), "a~0b");
        assert_eq!(escape_pointer("~~"), "~0~0");
    }

    #[test]
    fn escape_pointer_slash() {
        assert_eq!(escape_pointer("a/b"), "a~1b");
        assert_eq!(escape_pointer("path/to/thing"), "path~1to~1thing");
    }

    #[test]
    fn escape_pointer_both() {
        assert_eq!(escape_pointer("a/b~c"), "a~1b~0c");
        // Order matters: ~ must be escaped first
        assert_eq!(escape_pointer("~/"), "~0~1");
    }

    #[test]
    fn escape_unescape_roundtrip() {
        let cases = ["simple", "a/b", "c~d", "a/b~c/d~e", "~/~"];
        for case in cases {
            assert_eq!(unescape_pointer(&escape_pointer(case)), case);
        }
    }

    #[test]
    fn locator_server_name_with_slash_and_tilde() {
        // Regression: server names containing '/' and '~' must be escaped in pointers
        // and the locator must still resolve them correctly.
        let source = r#"{
  "mcpServers": {
    "my/server": {
      "command": "npx"
    },
    "tilde~name": {
      "command": "node"
    }
  }
}"#;
        let map = JsonLocationMap::from_source(source);

        // The locator internally uses escape_pointer, so keys with / and ~ work
        let slash_server = map.get("/mcpServers/my~1server").unwrap();
        assert_eq!(slash_server.start_line, 3);

        let tilde_server = map.get("/mcpServers/tilde~0name").unwrap();
        assert_eq!(tilde_server.start_line, 6);

        // Nested access still works
        let slash_cmd = map.get("/mcpServers/my~1server/command").unwrap();
        assert_eq!(slash_cmd.start_line, 4);

        let tilde_cmd = map.get("/mcpServers/tilde~0name/command").unwrap();
        assert_eq!(tilde_cmd.start_line, 7);
    }
}
