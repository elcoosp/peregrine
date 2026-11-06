//! Deterministic static-archive (`!<arch>`) builder for tests and benches.
//!
//! Mirrors what Apple's `libtool`/`ranlib` emit: `!<arch>\n` magic, a
//! `__.SYMDEF SORTED` first member (u32 count, `(strx, member header
//! offset)` pairs in name order, NUL-terminated string table) and the member
//! objects in insertion order with blank metadata fields and even-byte
//! padding. Building the same archive twice yields identical bytes.
//!
//! The index is derived from the member objects themselves: every external
//! `N_SECT` symbol of a member enters the table (undefined-only references
//! do not), so the S7 lazy-pull path sees exactly what `ranlib` would see.

/// Accumulates object members and emits the deterministic archive bytes.
#[derive(Debug, Clone)]
pub struct ArchiveBuilder {
    name: String,
    members: Vec<(String, Vec<u8>)>,
}

impl ArchiveBuilder {
    /// Starts an empty archive named `name` (diagnostics only).
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            members: Vec::new(),
        }
    }

    /// The archive name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Appends one member (an object's bytes) under `member_name`.
    pub fn add_member(&mut self, member_name: &str, object_bytes: Vec<u8>) {
        self.members.push((member_name.into(), object_bytes));
    }

    /// Number of accumulated members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// True when the archive has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Assembles the archive bytes: magic, `__.SYMDEF SORTED` table, then
    /// the members in insertion order.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        // ---- symbol table -------------------------------------------------
        // (name, member index) for every defined external symbol of every
        // member, sorted by name ("SORTED").
        let mut entries: Vec<(Vec<u8>, usize)> = Vec::new();
        for (member_index, (_, bytes)) in self.members.iter().enumerate() {
            for sym in member_defined_externals(bytes) {
                entries.push((sym, member_index));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut strings: Vec<u8> = Vec::new();
        let mut strx: Vec<u32> = Vec::with_capacity(entries.len());
        for (name, _) in &entries {
            strx.push(strings.len() as u32);
            strings.extend_from_slice(name);
            strings.push(0);
        }
        let mut symtab: Vec<u8> = Vec::with_capacity(4 + entries.len() * 8 + strings.len());
        symtab.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, (_, member_index)) in entries.iter().enumerate() {
            symtab.extend_from_slice(&strx[i].to_le_bytes());
            // Placeholder; the header offsets are patched after layout.
            symtab.extend_from_slice(&0u32.to_le_bytes());
            let _ = member_index;
        }
        symtab.extend_from_slice(&strings);

        // ---- layout -------------------------------------------------------
        // Member i's header offset = 8 (magic) + symtab block + all previous
        // member blocks (header + size + pad).
        let symtab_block = 60 + symtab.len() + (symtab.len() % 2);
        let member_blocks: Vec<usize> = self
            .members
            .iter()
            .map(|(_, bytes)| 60 + bytes.len() + (bytes.len() % 2))
            .collect();
        let mut member_offsets: Vec<u32> = Vec::with_capacity(self.members.len());
        let mut cursor = 8 + symtab_block;
        for block in &member_blocks {
            member_offsets.push(cursor as u32);
            cursor += block;
        }
        // Patch the member offsets into the table.
        for (i, (_, member_index)) in entries.iter().enumerate() {
            let off_field = 4 + i * 8 + 4;
            symtab[off_field..off_field + 4]
                .copy_from_slice(&member_offsets[*member_index].to_le_bytes());
        }

        // ---- emit ---------------------------------------------------------
        let mut out: Vec<u8> = b"!<arch>\n".to_vec();
        out.extend_from_slice(&member_header("__.SYMDEF SORTED", symtab.len()));
        out.extend_from_slice(&symtab);
        if symtab.len() % 2 == 1 {
            out.push(b'\n');
        }
        for (name, bytes) in &self.members {
            out.extend_from_slice(&member_header(name, bytes.len()));
            out.extend_from_slice(bytes);
            if bytes.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }
}

/// One 60-byte `ar` member header with blank metadata (deterministic).
fn member_header(name: &str, size: usize) -> Vec<u8> {
    let mut h = vec![b' '; 60];
    let name_bytes = name.as_bytes();
    let n = name_bytes.len().min(16);
    h[..n].copy_from_slice(&name_bytes[..n]);
    h[16] = b'0'; // mtime
    h[28] = b'0'; // uid
    h[34] = b'0'; // gid
    h[40] = b'0'; // mode
    let size_text = size.to_string();
    h[48..48 + size_text.len()].copy_from_slice(size_text.as_bytes());
    h[58] = b'`';
    h[59] = b'\n';
    h
}

/// The defined external symbol names of one relocatable object, in symtab
/// order (parsed through the `pgr-format` primitives — no allocation-heavy
/// object model here; fixtures stay dependency-light).
fn member_defined_externals(bytes: &[u8]) -> Vec<Vec<u8>> {
    let Ok(header) = pgr_format::MachHeader64::parse(bytes) else {
        return Vec::new();
    };
    let Ok(mut it) = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    ) else {
        return Vec::new();
    };
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Symtab {
            continue;
        }
        let Ok(st) = pgr_format::SymtabCommand::parse(cmd.bytes, 0) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for i in 0..st.nsyms {
            let Ok(sym) = pgr_format::cursor::pod_read_unaligned_at::<pgr_format::Nlist64>(
                bytes,
                st.symoff as usize + i as usize * 16,
            ) else {
                return names;
            };
            let defined_external = sym.is_external()
                && !sym.is_stab()
                && sym.n_type & 0x0e == pgr_format::consts::N_SECT;
            if !defined_external {
                continue;
            }
            let str_off = st.stroff as usize + sym.n_strx as usize;
            let Some(rest) = bytes.get(str_off..) else {
                continue;
            };
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            names.push(rest[..end].to_vec());
        }
        return names;
    }
    Vec::new()
}
