# Sections

Sections are the fundamental building block of the PE data. They contain the content of the file, including the executable code, data, resources and other executable artifacts.

Fibratus obtains the number of sections, and for each section encountered in the PE data, its name and size is fetched. For example, the code section is called `.text` and the data section is called `.data`. Sometimes the malware specimens tamper the PE structure and alter sections. You can hunt for a non-standard number of sections in the executable or detect extraneous sections by checking the data surfaced by Fibratus.

### Reading extended section data {docsify-ignore}

For a full-blown section parsing, you can enable the `read-sections` option. This instructs the PE parser to read the underlying section bytes for the purpose of computing the `md5` hash of each section. It is possible to write filter expressions that involve evaluating the section attributes.

For example, to match against specific `.text` section `md5` hash, you would write the `pe.sections[.text].md5 = '0464997eb36c70083164c666d53c6af3'` filter.
