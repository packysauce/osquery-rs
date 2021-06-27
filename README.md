# osquery-rs
Write osquery external plugins (the ones with that use thrift via unix) in Rust!

# about _osquery_
osquery is a really neat gadget that gives you access to all kinds of OS-related data via SQL. In a sense, it's all right there in the name.

# about _this repo_
This is just enough to be able to write a plugin in Rust and successfully talk to osquery. So far you can do tables!

# todos:
- [ ] more plugin types
- [ ] macro for only needing to define a "schema" (struct) and generate fn