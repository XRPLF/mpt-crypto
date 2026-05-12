# Conan lockfile

To achieve reproducible dependencies and protect against upstream
recipes being republished or dropping versions out from under us,
we use a [Conan lockfile](https://docs.conan.io/2/tutorial/versioning/lockfiles.html).

The `conan.lock` file at the repository root contains a "snapshot" of
the current dependency tree (versions, recipe revisions, package
revisions). It is implicitly used when running `conan` commands, so
you don't need to specify `--lockfile` on the CLI.

You have to update `conan.lock` every time you add a new dependency
or change the version / revision of an existing one (e.g. a version
bump in `conanfile.py`).

To regenerate, run from the repository root:

```sh
./conan/lockfile/regenerate.sh
```

The script uses a temporary `CONAN_HOME` to avoid pollution from the
user's local cache and ensures the `xrplf` remote is consulted first
(so any locally-patched recipes win over the public Conan Center).
