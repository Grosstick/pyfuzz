# Fuzzing 101 - My Notes

notes i'm writing while learning about fuzzing. mostly from reading AFL docs and watching youtube talks

## What even is Fuzzing?

So basically fuzzing is when you throw random (or semi-random) data at a program to see if it breaks.

The loop is pretty simple:
```
1. take valid input
2. mess with it randomly 
3. feed it to the program
4. if crash -> save it
5. goto 1
```

## Types of Fuzzing

### Mutation-based (dumb fuzzing)

You just take good input and randomly change stuff:
- flip bits
- insert random bytes
- delete chunks
- put in weird values like -1 or MAX_INT

pros: easy to implement, dont need to understand the format
cons: most inputs get rejected early bc theyre garbage

This is what I did in mutators.py

### Generation-based (smart fuzzing)

Generate inputs from a grammar:
```
json := object | array
object := "{" members "}"
...
```

I started implementing this but didn't finish (see generators.py). Its harder than mutation-based because you need to define the grammar for each format.

### Coverage-guided

Track what code each input runs. Keep inputs that find new code paths.

```python
if found_new_path:
    corpus.append(input)  # mutate this more later
```

AFL and libFuzzer do this. I tried to do something similar but without actual instrumentation its kinda fake tbh

## Why does this find bugs??

Parsers have SO many edge cases that devs dont think about:
- empty input?
- 10GB input?
- null bytes in the middle?
- nesting 1000 levels deep?
- negative numbers where you expect positive?

Humans write if/else for cases they think of. Fuzzers find the cases they didnt think of.

## Bugs fuzzers find

- buffer overflows - input too long
- integer overflows - numbers wrap around
- format strings - user input with %s %n etc
- null pointer stuff
- infinite loops - hangs on certain input

## My fuzzing loop

tried to copy AFL but way simpler:

```
          ┌─────────┐
          │ Corpus  │ (seed inputs)
          └────┬────┘
               │
               ▼
          ┌─────────┐
          │ Mutator │ (mess with it)
          └────┬────┘
               │
               ▼
          ┌─────────┐
          │ Target  │ (run it)
          └────┬────┘
               │
        crash? │ new path?
               │
               ▼
          ┌─────────┐
          │ Monitor │ (save crashes, update corpus)
          └─────────┘
```

## Interesting values

AFL uses these numbers bc they often cause bugs:

```python
# 8-bit
[0, 1, 127, 128, 255]

# 16-bit  
[0, 1, 32767, 32768, 65535]

# 32-bit
[0, 1, 2147483647, 2147483648, 4294967295]
```

Why?
- 0 → off by one
- 127/128 → signed byte boundary (127 is max positive, 128 overflows to negative)
- 255 → max unsigned byte
- 32767/32768 → same but for shorts
- 2147483647 → MAX_INT

I copy-pasted these into my mutator

## Stuff I read/watched

- AFL Technical Details doc - super dense but good
- The Fuzzing Book (fuzzingbook.org) - free online, helped a lot
- some google talks on youtube about libfuzzer

## Things I still dont really get

- How does AFL's fork server work exactly? something about cloning processes fast
- What's the best way to minimize corpus? 
- Grammar inference sounds cool but seems hard
- How do real fuzzers deduplicate crashes? stack trace hashing?

---

last updated: working on this project
