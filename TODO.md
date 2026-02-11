# TODO

## need to do
- [ ] async http requests (currently slow)
- [ ] better crash dedup - currently just hashing error msg 
- [ ] finish grammar-based generation

## would be nice
- [ ] integrate with coverage.py for actual coverage
- [ ] fuzz python functions directly not just http
- [ ] corpus minimization
- [ ] web ui? maybe overkill

## known bugs
- http target sometimes misses connection errors
- memory grows with big corpus, probably a leak somewhere
- seeds loading doesnt check if files are valid

## done
- [x] basic mutations 
- [x] http fuzzing
- [x] crash saving
- [x] cli
- [x] vulnerable test app
- [x] docs
