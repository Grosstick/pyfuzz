# Dev Notes

random notes from building this

## timeline (ish)

### week 1 - figuring out what to build
- watched a bunch of fuzzing talks
- read the AFL technical doc (took like 3 reads to understand it)
- decided to make an http fuzzer since thats more relevant for web stuff

### week 2 - basic mutations
- bit flip was easy
- the interesting values thing from AFL is clever, just copied those
- first version was super buggy, crashed more than the target lol

### week 3 - actually making it work
- added http target using requests library
- timeout handling was annoying to get right
- corpus management is trickier than i thought

### week 4 - cleanup
- added cli with argparse (copied structure from another project)
- made the vulnerable app for testing
- wrote docs

## problems i ran into

**coverage tracking**
real fuzzers instrument code at compile time. cant do that for random http endpoints. ended up using response characteristics (status code, size, error patterns) as a proxy. its not great but idk how else to do it for black-box http fuzzing

**its slow**
python + http = slow. AFL does 10k+ execs per second, im getting maybe 100 over http. could maybe use async but that seemed complicated

**crash dedup**
my approach is just hashing the error message which is pretty naive. real fuzzers look at stack traces and crash locations. good enough for learning tho

**the grammar stuff**
started on generators.py but its more work than i expected. would need to define grammars for each format (json, xml, etc). maybe later

## things i'd do differently

- should have started simpler, just file fuzzing first
- spent too long on the cli, could have been simpler
- would be nice to have tests but kept putting it off

## resources

- https://lcamtuf.coredump.cx/afl/technical_details.txt (must read)
- https://www.fuzzingbook.org/ (good intro)
- youtube talks from google security team
- bunch of stackoverflow for python stuff

## random ideas for later

- use coverage.py for actual python code coverage
- async http with aiohttp
- maybe a simple web ui to see progress?
- try fuzzing actual python parsers directly instead of over http
