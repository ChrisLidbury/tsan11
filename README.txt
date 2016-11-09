ThreadSanitizer for C++11 (tsan11) research repository
===============================

This repo contains tsan11 for the purposes of experimenting with the C++11
memory model and techniques for performing dynamic analysis of programs written
for C++11.

This repo is not inteded to work with the main repo, so will not be synced
regularly. The svn files are here, so it can be synced if necessary.

The initial commit contains compiler-rt at r286385 as found in the main SVN repo
for compiler-rt. The second commit contains the changes used by our paper
"Dynamic Race Detection For C++11" in POPL17, the resulting repo we call tsan11.

The main branch contains just the basic tsan11, research projects are kept in
their respective branches. If something is deemed to be useful to both the basic
tsan11 tool and other research branches, then it can be merged with the master.

================================
