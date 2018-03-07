# rpmfile2 - files+type in .rpm packages

The `rpmfile2` program lists filenames, along with their magic types,
as determined by `file(1)`, in `.rpm` packages.  This is a reimplementation
of the original [rpmfile(1)](https://linux.die.net/man/1/rpmfile) script,
written many years ago, part of the `rpmdevtools` package.  This time I use
[rpmcpio](https://github.com/svpv/rpmcpio) and `libmagic(3)` libraries,
thereby obviating the need to extract the full archive into a temporary
directory.  As a further measure to improve performance, a separate thread
is spawned to run the _magic_ routines, in parallel with the decompressor.
The output should be identical to that of `rpmfile(1)`, more or less.
Although one difference is that hardlinks are now identified properly.
