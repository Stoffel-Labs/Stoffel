# Stoffel-Lang Compiler

A compiler for the Stoffel programming language, with support for generating bytecode compatible with the StoffelVM.

## Features

- Modern syntax inspired by Rust, Python, and JavaScript
- Strong static typing with type inference
- Register-based bytecode generation
- VM-compatible binary output
- Optimizations for efficient code execution

## Installation

### Prerequisites

- Rust and Cargo (latest stable version)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/Stoffel-Lang.git
cd Stoffel-Lang

# Build the project
cargo build --release

# The compiler binary will be available at target/release/stoffellang
```

## Usage

### Basic Compilation

```bash
# Compile a source file
./stoffellang path/to/source.stfl

# Enable optimizations
./stoffellang -o path/to/source.stfl

# Set optimization level (0-3)
./stoffellang -O2 path/to/source.stfl

# Print intermediate representations (tokens, AST)
./stoffellang --print-ir path/to/source.stfl
```

### Generating VM-Compatible Binaries

The compiler can generate binary files that are compatible with the StoffelVM:

```bash
# Generate a VM-compatible binary (outputs to source.stflb by default)
./stoffellang -b path/to/source.stfl

# Specify output file
./stoffellang -b -o output.stflb path/to/source.stfl
```

## Language Examples

StoffelLang is Pythonic: indentation-based blocks, `def` for functions,
`var` for (mutable) variables, and `#` comments.

### Hello World

```python
def main() -> None:
  print("Hello, world!")
```

### Variables and Types

```python
def main() -> None:
  var x: int32 = 42i32      # sized integers: int8..int64, uint8..uint64
  var y = 3.14              # float (exponents work too: 2.5e-2)
  var f: fix64 = 1.5        # fixed-point (MPC-friendly): fix32 / fix64
  var name = "Stoffel" + "!"
  var is_active = True
  print(name, len(name), x, y, f, is_active)
```

### Functions

```python
# Literal default values and named arguments are supported.
def add(a: int64, b: int64 = 7) -> int64:
  return a + b

def main() -> int64:
  return add(5) + add(b: 2, a: 1)
```

### Control Flow

```python
def main() -> int64:
  var sum = 0
  for i in 0..10:        # ranges are end-EXCLUSIVE
    if i % 2 == 1:
      continue
    if i > 6:
      break
    sum += i
  while sum < 100:
    sum = sum * 2
  return sum
```

### Imports and aliases

```python
import utils as u                 # module: utils.stfl
import utils.calculate as calc   # function calculate in utils.stfl
import pkg.tools as tools        # module: pkg/tools.stfl

def main() -> int64:
  return calc(3) + u.calculate(4)
```

For `import module.function as alias`, call `alias(...)` directly. Omitting
`as alias` binds the exported function's own name. Only the selected export is
introduced; its helpers stay in the defining module and are not added to the
caller's scope.
Default, named, and variadic arguments work through imported aliases too.

A real nested module takes precedence: if `utils/calculate.stfl` exists,
`import utils.calculate as calc` imports that module, and its functions are
called as `calc.function(...)`. Otherwise the compiler looks for the exported
function in `utils.stfl`. Missing exports and conflicting aliases produce
errors at the import statement. Quoted filesystem imports retain module
semantics, for example `import "../utils.stfl" as u`.

### Bitwise Operations

`and`, `or`, `xor` are logical on bools and bitwise on matching integer
types (Nim-style); `shl`/`shr` are the shift operators.

```python
def main() -> int64:
  var mask = 12 and 10   # 8
  var bits = 12 xor 10   # 6
  var shifted = 1 shl 4  # 16
  return mask + bits + shifted
```

### Pythonic Conveniences

```python
enum Color:
  Red
  Green
  Blue          # auto-increment int64 constants; Color.Blue == 2

def total(*xs) -> int64:   # varargs pack into a list
  var sum = 0
  for x in xs:
    sum += x
  return sum

def main() -> int64:
  var xs: list[int64] = [1, 2, 3, 4, 5]
  var mid = xs[1:3]                       # slicing (negative bounds work)
  var last = xs[-1]                       # negative indexing
  var evens = [x for x in xs if x % 2 == 0]  # comprehensions
  assert 2 in xs, "membership with 'in'"  # assert with optional message
  var s = f"sum is {last}"                # f-strings (variable interpolation)
  match last:                             # match on literals; _ is default
    case 5:
      print(s)
    case _:
      pass
  return total(1, 2) + len(evens) + len(mid)
```

### Secret (MPC) Values

```python
def main() -> int64:
  var a: secret int64 = Share.from_clear(10)
  var b: secret int64 = a + 5
  return b.reveal()
```

## VM Compatibility

The compiler now supports generating binary files that are compatible with the StoffelVM. This allows Stoffel programs to be executed on any platform that supports the VM.

The binary format includes:
- A rich type system (integers, floats, strings, booleans, arrays, objects)
- Function definitions with metadata
- Optimized bytecode instructions
- Constant pools for efficient value storage

## Learn More

To learn more about what you can build with Stoffel, visit 
[stoffelmpc.com](https://stoffelmpc.com?utm_source=github&utm_medium=readme&utm_campaign=stoffel-lang-repo&utm_term=mpc)

## Field constants, namespaces, and scope

`Share.from_field(field_bytes: bytes) -> Share` constructs a share of a **public**
constant in the active MPC field. Supply the same canonical `Field.*` encoding on
every party. Construction is local and consumes no preprocessing material.
It preserves the full field value, including values above 64 bits, and rejects
truncated, noncanonical, or trailing bytes.

```python
def main() -> bytes:
  var f: bytes = Field.mul(Field.from_int(4294967296), Field.from_int(4294967296))
  var s: Share = Share.from_field(f)
  return Share.open_field(s)
```

The runtime identifies these values as `SecretField`. `Share.random_field`,
`Share.add_field`, and `Share.mul_field` also produce this type. Use `open_field`
or `batch_open_field` to open them. Integer scalar arithmetic and field arithmetic
preserve the field domain; bounded scalar opening, fixed-point scalar promotion,
and integer `retag` reject it. Pairwise share arithmetic requires matching types.
To promote an integer share to the field domain, use
`Share.add_field(integer_share, Field.zero())`. Raw field operations reject
fixed-point shares because those payloads have a scale factor.

This adds binary format version 11 and a distinct serialized share tag; existing
tags retain their values. Field shares can be stored and returned as raw shares.
Scalar-only SDK and generated-client interfaces report an unsupported-type error;
use raw client I/O for this domain. C `CShareType` uses kind 4 with width 0.

`Field`, `Bytes`, `Mpc`, and the other builtin namespaces are method containers,
not annotation types or values. Use `bytes` for field encodings and byte arrays.
`Share`, `Object`, and `Closure` remain opaque value types. Variables may be
declared before assignment, but a read must have an initialized value on every
path reaching it. This also applies to clear scalars and user-object fields.
The current VM evaluates both operands of `and`/`or`; use `if` to guard a read
that requires initialization. Lists default to empty lists and secret numeric/bool variables retain their zero
defaults. User objects allocate their nested objects and list fields; their other
fields need assignment. The checker follows object aliases and local initializer
helpers, and excludes paths ending in `return`, `break`, or `continue` when
joining control flow. Passing an incompletely initialized object to an unknown
or imported helper is rejected; construct it completely before crossing that
boundary. Type aliases and inherited fields use the same defaults as their
resolved types.

Client-output metadata follows helper arguments and returns, including imported
helpers and literal closure targets, lists, field access, aliases, reassignment,
and statically bounded loops. Named/default arguments and variadic argument lists
use their checked call-site bindings. Runtime loop backedges are joined until
stable, so domain changes after later iterations are included. It preserves
integer widths, fixed-point precision, and the full-field domain.
An ambiguous domain, unknown output-list length, or runtime-bounded output loop
produces a source diagnostic instead of an integer fallback. Analysis runs before
optimization, so these checks apply at O0 through O3. Recursion and loop analysis
are bounded; changing facts in a nonconverging runtime loop become unknown.
Outputs that depend on those facts need a simpler static shape. Scalar consumers still enforce the runtime Share tag: an annotation is
not a conversion from the field domain to a bounded scalar.

List repetition requires a clear integer count in either operand order. For a
share multiplied by field bytes, use `Share.mul_field(share, field_bytes)`.

Programs may use either script-style executable top-level statements or an
explicit `def main`, but cannot mix the two. Imported modules contain declarations;
executable module initialization and mutable globals are not implemented.
Functions cannot implicitly capture outer variables. Pass values as parameters
or use explicit closure upvalues.
