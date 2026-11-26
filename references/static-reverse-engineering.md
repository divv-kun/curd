# Static reverse engineering

Identify the file from its headers and record its architecture, format, and hash. Use a copy for analysis and inspect it without launching it. Start with the section table, visible strings, imports, and exports.

Trace references from strings or imports to the functions that use them. Treat symbols and decompiler output as hypotheses. Check important conclusions against the disassembly and record addresses or offsets so someone else can follow the same evidence.

Describe the behavior the evidence supports. Keep uncertain behavior, missing components, and assumptions explicit in the writeup.

Upstream reference [Ghidra documentation](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs).
