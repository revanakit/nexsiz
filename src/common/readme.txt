NEXSIZ :: common

Shared foundation layer.

Holds configuration (Config + sub-structs), unified error type
(NexsizError), core data types (TestCase, ExecutionResult,
OutcomeClass, Field, Message, …), and small utilities (RNG,
duration formatting, helpers).

Every other module depends on this crate-local foundation.
No protocol logic, no execution, no I/O beyond config loading.
