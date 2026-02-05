# PyFuzz

A python fuzzer I built to learn how fuzzing works. 

## what is this

I wanted to understand how fuzzers like AFL and libFuzzer work internally, so I built a simple one from scratch. It can fuzz HTTP APIs by mutating request bodies and looking for crashes.

**note**: this is a learning project, not meant for actual security testing. use AFL++ or atheris for real work.

## features

- mutation-based fuzzing (bit flips, interesting values, etc)
- basic coverage-guided feedback (kinda)
- http api fuzzing
- crash detection and saving

## install

```bash
pip install -r requirements.txt
```

## quick start

```bash
# terminal 1: run the test app
python examples/vulnerable_app.py

# terminal 2: fuzz it
python main.py --target http://localhost:5000/api/parse
```

the vulnerable app has a bunch of intentional bugs for testing

## project structure

```
pyfuzz/
├── pyfuzz/
│   ├── core/         # fuzzing engine, mutators
│   ├── targets/      # http target
│   └── monitors/     # crash detection
├── examples/         # vulnerable test app
├── docs/             # my learning notes
├── seeds/            # seed inputs
└── crashes/          # saved crashes
```

## docs

- `docs/FUZZING_101.md` - my notes on fuzzing concepts
- `docs/AFL_COMPARISON.md` - how this relates to real tools
- `docs/DEV_NOTES.md` - random dev notes

## status

working but basic. see TODO.md for whats missing/broken.

main limitations:
- coverage tracking is fake (just looks at responses)
- pretty slow compared to real fuzzers
- no grammar-based generation yet

## disclaimer

for educational purposes. only fuzz things you have permission to test.
