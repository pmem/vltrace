bin2txt converter
=================

bin2txt converts vltrace logs from binary to text format.

bin2txt as a converter is a part of pmemfile's analyzing tool (antool),
so the following files:

- converter.py
- exceptions.py
- syscallinfo.py
- syscall.py
- syscalltable.py
- utils.py

have to be identical in both projects:

1) https://github.com/pmem/vltrace/tree/master/tools/bin2txt
2) https://github.com/pmem/pmemfile/tree/master/src/tools/antool

Keep in mind to synchronize them!


### CONTACTS ###

For more information about this tool contact:

 - Lukasz Dorau (lukasz.dorau at intel.com)

or create an issue [here](https://github.com/pmem/vltrace/issues).
