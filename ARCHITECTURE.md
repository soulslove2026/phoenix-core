# Architecture

Slice 0 is one stateless HTTP process using only the Node.js standard library. It proves lifecycle, configuration, health, readiness, logging, testing, CI, and container execution. It does not establish the final backend framework.
