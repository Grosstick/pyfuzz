# How PyFuzz compares to real tools

trying to understand how my little project relates to actual fuzzers

## vs AFL

AFL is like THE fuzzer everyone talks about. heres how mine compares:

| thing | AFL | mine |
|-------|-----|------|
| mutations | tons | basic ones |
| coverage | real instrumentation | fake (response-based) |
| fork server | yes | no idea how to do this |
| speed | like 10k/sec | maybe 100/sec lol |
| parallel | yes | nope |

### what i learned from AFL

read the technical details doc. main takeaways:
- the interesting values table (boundary numbers that cause bugs)
- keeping inputs that find new paths
- different mutation strategies

### whats different

AFL actually instruments the code at compile time so it knows exactly what lines are being run. I cant do that for HTTP targets so I just look at the response (status code, size, error messages) as a proxy. not as good but its something

also AFL has this fork server thing that makes it spawn processes super fast. no clue how that works really

## vs libFuzzer

google's fuzzer, runs in-process

| thing | libFuzzer | mine |
|-------|-----------|------|
| in-process | yes | no (http) |
| sanitizers | ASan/MSan/etc | nope |
| speed | fast | slow |
| corpus merge | yes | no |

libfuzzer hooks into the coverage stuff that clang provides. way more sophisticated than what i have

## vs Atheris

python fuzzer from google. more fair comparison since mine is also python

| thing | Atheris | mine |
|-------|---------|------|
| python native | yes | yes |
| real coverage | yes (via libfuzzer) | no |
| speed | faster | slower |

atheris is what i should probably use for real python fuzzing. mine is more for learning how it works

## what real fuzzers have that i dont

1. **actual code coverage** - they instrument at compile time, I just guess from responses

2. **memory sanitizers** - ASan catches memory bugs. python doesnt really have this problem tho

3. **good crash dedup** - real fuzzers hash stack traces. i just hash error messages which is pretty bad

4. **corpus minimization** - remove redundant inputs. would be nice to add

5. **distributed fuzzing** - run on multiple machines. way out of scope lol

## why write my own then?

even tho real fuzzers are way better, building this helped me understand:
- how fuzzing actually works under the hood
- mutation strategies
- why coverage matters
- crash handling basics

reading about it is different from building it

## next steps

want to try:
- [ ] actually use AFL++ on something
- [ ] try atheris for python
- [ ] learn more about taint tracking (sounds cool)

## commands to try the real stuff

```bash
# AFL++ (linux)
sudo apt install afl++
afl-fuzz -i seeds -o output -- ./target @@

# Atheris
pip install atheris
```

---

writing my own fuzzer was def worth it for learning even if its not production quality
