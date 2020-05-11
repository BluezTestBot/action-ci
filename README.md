# action-ci

This is a Github Action for CI.

## Run and report

When the PR is created with set of patches, CI job starts and runs the tests.
If any of test fails, it send email to the submitter via mailing list by replying to the original email with failure details and update the result to PR comment.
If all tests pass, no report send to the submitter but it still updates the result to PR comment.

## Configuration

[config.ini](./config.ini) contains some configuration for test. See the file for details.

## Test Covered

Following tests are covered.

### CheckPatch

This test runs the [checkpatch.pl](https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl) and the configuration is in `.checkpatch.conf`.

```conf
.checkpatch

--no-tree
--no-signoff
--summary-file
--show-types
--max-line-length=80

--ignore COMPLEX_MACRO
--ignore SPLIT_STRING
--ignore CONST_STRUCT
--ignore FILE_PATH_CHANGES
--ignore MISSING_SIGN_OFF
--ignore PREFER_PACKED
--ignore COMMIT_MESSAGE
```

### Check gitlint

This test runs `gitlint` and its configuration is in [gitlint](./gitlint) file.

```ini
gitlint

[title-max-length]
line-length=72

[body-min-length]
min-length=1
```

### Check Build

This test checks if the tree can be built with a default configuration.

```bash
./bootstrap-configure --enable-external-ell
make
```

Note that it uses `ell` as an external library.

### Make Check

If the `checkbuild` passes, it run `make check`.
