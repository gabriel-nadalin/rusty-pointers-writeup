# Rusty Pointers — Writeup

Pwn (heap/glibc) em Rust, sem uma linha de `unsafe`. Alvo: Ubuntu 20.04, glibc 2.31
(sem safe-linking). Exploit: `exploit.py`.

## A vulnerabilidade

`get_ptr` (main.rs:83) "lava" um lifetime e devolve `&'static mut`:

```rust
fn get_ptr<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
    fn ident<'a, 'b, T: ?Sized>(_: &'a &'b (), v: &'b mut T) -> &'a mut T { v }
    let f: fn(_, &'a mut T) -> &'b mut T = ident;
    f(S, x)
}
```

`get_rule`/`get_law` fazem `Box::new(...)`, passam por `get_ptr` e retornam a
referência. O `Box` é liberado no `return`, mas a referência continua válida para
o compilador. Resultado: `rules: Vec<&'static mut [u8; 64]>` guarda handles para
chunks **já liberados** — use-after-free com escrita. É a falha antiga de
lifetime (rust-lang/rust#25860); rustc 1.99 já rejeita esse código, por isso o
binário de 1.75 é a fonte da verdade.

## Heap

`Box` usa o alocador do sistema (`malloc`/`free`).

| Alocação | Tamanho | Destino ao liberar |
|---|---|---|
| `Box<[u8; 64]>` (Rule/Note) | chunk `0x50` | tcache |
| Box de 2000 bytes (Law) | chunk `0x7e0` | unsorted bin |

- tcache: LIFO por tamanho, até 7 por bucket, `next`/`key` nos 16 primeiros bytes.
- unsorted bin: lista duplamente ligada; `fd`/`bk` apontam para `main_arena` (libc).

## Primitivas

1. **Leak de libc**: a Law libera um chunk de `0x7e0` no unsorted bin e o
   programa imprime `fd` e `bk`, que valem o mesmo endereço
   (`&main_arena.bins[0]`, em libc).
2. **Overlap**: a próxima alocação de `0x50` reaproveita o chunk que a Rule
   ainda referencia; escrever pela Rule altera o objeto que o Note possui.
3. **Tcache poisoning**: com o chunk livre, escrever pela Rule sobrescreve o
   `next` da tcache. A próxima `malloc` do mesmo tamanho retorna o endereço
   escolhido.

Detalhe importante: `tcache_get` decrementa um contador e para de consultar o
bucket quando ele chega a zero — então é preciso **duas** entradas na lista
antes do poisoning.

## Cadeia

| # | Ação | Estado do heap |
|---|---|---|
| 1 | Law | leak de libc; base = leak − `0x1ecbe0` |
| 2 | 2 Notes, deletar as duas | tcache `B -> A`, contador 2 |
| 3 | Criar Rule | aloca `B`, libera de novo; `rules[0]` aponta para `B` |
| 4 | Editar Rule com `__free_hook` | `B.next = __free_hook` |
| 5 | Criar 2 Notes | `notes[0] = B`, `notes[1] = &__free_hook` |
| 6 | `notes[0] = "/bin/sh"`, `notes[1] = system` | `__free_hook = system` |
| 7 | Deletar o Note 0 | `free(B)` → `system("/bin/sh")` |

A ordem é obrigatória: a tcache é LIFO e de tamanho exato, então qualquer
alocação/liberação de `0x50` no meio muda quem cai onde.

## Offset da libc (medido, não copiado)

Roda-se o binário local uma vez, captura-se o leak e a base real da libc via
`/proc/<pid>/maps` (`p.libs()` do pwntools):

```python
p = process(BIN, cwd=CHAL)
p.recvuntil(b'> '); p.sendline(b'5')
leak = int(p.recvline().split(b',')[0], 16)
base = [b for k, b in p.libs().items() if 'libc' in k][0]
print(hex(leak - base))        # 0x1ecbe0
```

ASLR muda a base, não a diferença (execuções distintas dão o mesmo offset).
Conferência: `(leak - 0x1ecbe0) & 0xfff == 0` e o leak sempre termina em `0xbe0`.

## Execução

```bash
python3 exploit.py                                  # local
python3 exploit.py --gdb                            # depuração
python3 exploit.py --remote rustyptrs.chal.uiuc.tf  # TLS
```

O exploit usa `dist/` **relativo ao próprio script** (`ROOT/dist/rusty_ptrs`,
`ROOT/dist/libc-2.31.so`) e roda com `cwd = ROOT`. O binário em `dist/` foi
remendado com interpreter relativo (`dist/lib/ld-linux-x86-64.so.2`) e
`RUNPATH=$ORIGIN/lib`; `dist/lib/` contém os symlinks de SONAME e um stub de
`libdl.so.2` (o binário não importa nada dela). `flag.txt` fica na raiz para o
`cat flag.txt` local.

Resultado local: shell obtido e `cat flag.txt` imprime a flag. Símbolos
(`system`, `__free_hook`) vêm do próprio `libc-2.31.so` distribuído.

## Container (fidelidade)

`Dockerfile` mínimo: `ubuntu:20.04` com glibc 2.31 nativa, socat, sem nsjail/PoW.

```bash
docker build -t rusty-pointers:local .
docker run --rm -p 127.0.0.1:1337:1337 rusty-pointers:local
python3 exploit.py --remote 127.0.0.1 --no-ssl
```

No build, o binário vindo de `dist/` (remendado para o debug local) tem
interpreter e RUNPATH restaurados para o padrão, então roda com a libc do
container. Verificado: offsets (`0x1ecbe0`, `system`, `__free_hook`) batem com
o `libc-2.31.so` distribuído.

O Dockerfile oficial (base kctf) não é reproduzível localmente sem o cluster
kCTF, PoW e `--privileged`; para testar o exploit, este container basta.
