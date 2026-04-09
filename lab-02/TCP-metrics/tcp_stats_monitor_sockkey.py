#!/usr/bin/env python3
# tcp_stats_monitor_sockkey.py
# Monitor de fluxos TCP via eBPF com tabela dinâmica (curses TUI).
# Conexões novas são adicionadas, conexões fechadas (TCP_CLOSE / TCP_TIME_WAIT
# sem atividade recente) são removidas automaticamente.
#
# Uso: sudo python3 tcp_stats_monitor_sockkey.py [opções]
#   --bpf-src FILE          arquivo .c do BPF (padrão: tcp_stats_sockkey.c)
#   --collect-interval N    intervalo de coleta em segundos (padrão: 0.3)
#   --display-interval N    intervalo de refresh da TUI em segundos (padrão: 0.5)
#   --ttl N                 segundos sem atividade para remover entrada (padrão: 30)
#   --state-filter S[,S]    filtrar por estado(s) TCP  ex: ESTABLISHED
#   --sort-by CAMPO         pkts | bytes | rtt | retr | state (padrão: pkts)
#   --verbose               exibe sock_ptr e cc_ptr
################################################################################
### # Básico
### sudo python3 tcp_stats_monitor_sockkey.py

### # Só conexões estabelecidas, com coluna de bytes
### sudo python3 tcp_stats_monitor_sockkey.py --state-filter ESTABLISHED --verbose

### # Coleta mais rápida
### sudo python3 tcp_stats_monitor_sockkey.py --collect-interval 0.1
################################################################################

import curses, threading, time, sys, os, bisect, struct, socket, argparse

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

BPF_SOURCE = "tcp_stats_sockkey.c"

TCP_STATES = {
    1:  "ESTABLISHED",
    2:  "SYN_SENT",
    3:  "SYN_RECV",
    4:  "FIN_WAIT1",
    5:  "FIN_WAIT2",
    6:  "TIME_WAIT",
    7:  "CLOSE",
    8:  "CLOSE_WAIT",
    9:  "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
}

# Estados que indicam conexão encerrada — removidos com metade do TTL
CLOSED_STATES = {6, 7, 11}  # TIME_WAIT, CLOSE, CLOSING

SORT_KEYS = {
    "pkts":  lambda r: r["pkts"],
    "bytes": lambda r: r["bytes_sent"],
    "rtt":   lambda r: r["rtt_ms"],
    "retr":  lambda r: r["retrans"],
    "state": lambda r: r["state"],
}

# ---------------------------------------------------------------------------
# Utilitários de rede
# ---------------------------------------------------------------------------

def ip_ntoa(addr: int) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", addr & 0xFFFFFFFF))
    except Exception:
        return "?.?.?.?"

def port_to_host(p: int) -> int:
    try:
        return socket.ntohs(p & 0xFFFF)
    except Exception:
        return p & 0xFFFF

def state_name(state: int) -> str:
    return TCP_STATES.get(state, f"?({state})")

def human_bytes(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}T"

# ---------------------------------------------------------------------------
# Resolução de símbolos via /proc/kallsyms
# ---------------------------------------------------------------------------

class KallsymsResolver:
    def __init__(self):
        self._addrs: list = []
        self._names: list = []
        self._loaded = False
        self._load()

    def _load(self):
        try:
            addrs, names = [], []
            with open("/proc/kallsyms") as f:
                for line in f:
                    parts = line.split(None, 2)
                    if len(parts) < 3:
                        continue
                    try:
                        addr = int(parts[0], 16)
                    except ValueError:
                        continue
                    name = parts[2].split("\t")[0].strip()
                    addrs.append(addr)
                    names.append(name)
            if addrs:
                self._addrs = addrs
                self._names = names
                self._loaded = True
        except Exception:
            pass

    @property
    def loaded(self) -> bool:
        return self._loaded

    def resolve(self, ptr: int) -> str:
        if not ptr or not self._loaded:
            return "unknown"
        i = bisect.bisect_right(self._addrs, ptr) - 1
        if i < 0:
            return "unknown"
        # Verifica se ptr está dentro do corpo do símbolo
        if i + 1 < len(self._addrs) and ptr >= self._addrs[i + 1]:
            return "unknown"
        if ptr == self._addrs[i]:
            return self._names[i]
        return f"{self._names[i]}+0x{ptr - self._addrs[i]:x}"

# ---------------------------------------------------------------------------
# FlowStore — ciclo de vida das conexões
# ---------------------------------------------------------------------------

class FlowStore:
    """
    Dicionário thread-safe de fluxos TCP indexado por sk_ptr.
    Conexões novas são inseridas; conexões inativas ou fechadas são eviccionadas.
    """

    def __init__(self, ttl_s: float = 30.0):
        self._lock               = threading.Lock()
        self._flows: dict        = {}          # sk_ptr -> row dict
        self._last_seen: dict    = {}          # sk_ptr -> time.monotonic()
        self._ttl_s              = ttl_s

    def update(self, sk_ptr: int, data: dict):
        with self._lock:
            self._flows[sk_ptr]      = data
            self._last_seen[sk_ptr]  = time.monotonic()

    def evict_stale(self):
        """Remove entradas expiradas. Chamado pela thread de coleta."""
        now = time.monotonic()
        with self._lock:
            to_del = []
            for sk_ptr, data in self._flows.items():
                age       = now - self._last_seen.get(sk_ptr, now)
                state_num = data.get("state_num", 0)
                # Conexões fechadas saem em TTL/2; demais em TTL completo
                limit = self._ttl_s / 2 if state_num in CLOSED_STATES else self._ttl_s
                if age > limit:
                    to_del.append(sk_ptr)
            for sk_ptr in to_del:
                del self._flows[sk_ptr]
                self._last_seen.pop(sk_ptr, None)

    def snapshot(self, sort_key=None, state_filter=None) -> list:
        with self._lock:
            rows = list(self._flows.values())
        if state_filter:
            rows = [r for r in rows if r["state_num"] in state_filter]
        if sort_key:
            rows.sort(key=sort_key, reverse=True)
        return rows

    def count(self) -> int:
        with self._lock:
            return len(self._flows)

# ---------------------------------------------------------------------------
# Thread de coleta BPF
# ---------------------------------------------------------------------------

def collector_thread(
    table,
    resolver: KallsymsResolver,
    store: FlowStore,
    interval: float,
    stop_event: threading.Event,
):
    while not stop_event.is_set():
        for k, v in table.items():
            sk_ptr = int.from_bytes(bytes(k), byteorder="little")

            if v.last_seen_ns == 0:
                continue

            addr      = v.addr
            state_num = v.last_state
            srtt_raw  = getattr(v, "srtt_us", 0)
            rtt_us    = getattr(v, "rtt_us",  0)
            cwnd      = getattr(v, "cwnd",    0)
            cc_ptr    = getattr(v, "cc_ops_ptr", 0)

            store.update(sk_ptr, {
                "sk_ptr":     sk_ptr,
                "s_ip":       ip_ntoa(addr.saddr),
                "d_ip":       ip_ntoa(addr.daddr),
                "s_port":     port_to_host(addr.sport),
                "d_port":     port_to_host(addr.dport),
                "pkts":       v.pkts_sent,
                "bytes_sent": v.bytes_sent,
                "retrans":    v.retransmits,
                "rtt_ms":     rtt_us / 1_000.0 if rtt_us else 0.0,
                "srtt_ms":    (srtt_raw >> 3) / 1_000.0 if srtt_raw else 0.0,
                "srtt_raw":   srtt_raw,
                "cwnd":       cwnd,
                "cc_name":    resolver.resolve(cc_ptr) if cc_ptr else "unknown",
                "cc_ptr":     cc_ptr,
                "state":      state_name(state_num),
                "state_num":  state_num,
                "last_seen":  v.last_seen_ns,
            })

        store.evict_stale()
        stop_event.wait(interval)

# ---------------------------------------------------------------------------
# TUI — tabela dinâmica com curses
# ---------------------------------------------------------------------------

# Cores por estado (índice do par curses)
STATE_COLOR = {
    "ESTABLISHED": 1,  # verde
    "LISTEN":      2,  # azul
    "SYN_SENT":    3,  # ciano
    "SYN_RECV":    3,
    "FIN_WAIT1":   4,  # amarelo
    "FIN_WAIT2":   4,
    "CLOSE_WAIT":  4,
    "TIME_WAIT":   4,
    "CLOSING":     5,  # vermelho fraco
    "CLOSE":       5,
    "LAST_ACK":    5,
}

def build_columns(verbose: bool) -> list:
    """Retorna lista de (label, largura, formatador)."""
    cols = [
        ("SOURCE",      21, lambda r: f"{r['s_ip']}:{r['s_port']}"),
        ("DESTINATION", 21, lambda r: f"{r['d_ip']}:{r['d_port']}"),
        ("STATE",       13, lambda r: r["state"]),
        ("PKTS",         9, lambda r: str(r["pkts"])),
        ("BYTES",        9, lambda r: human_bytes(r["bytes_sent"])),
        ("RETR",         6, lambda r: str(r["retrans"])),
        ("RTT ms",       9, lambda r: f"{r['rtt_ms']:.2f}"),
        ("CWND",         6, lambda r: str(r["cwnd"])),
        ("CC",          14, lambda r: r["cc_name"]),
    ]
    if verbose:
        cols += [
            ("SOCK_PTR",  18, lambda r: f"0x{r['sk_ptr']:016x}"),
            ("CC_PTR",    18, lambda r: f"0x{r['cc_ptr']:016x}"),
        ]
    return cols

def draw_header(stdscr, y: int, columns: list, max_x: int):
    stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
    line = ""
    for label, width, _ in columns:
        line += label[:width].ljust(width) + " "
    stdscr.addstr(y, 0, line[:max_x].ljust(max_x))
    stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)

def draw_row(stdscr, y: int, row: dict, columns: list, max_x: int, highlight: bool):
    state   = row.get("state", "")
    pair    = STATE_COLOR.get(state, 0)
    attr    = curses.color_pair(pair)
    if highlight:
        attr |= curses.A_REVERSE

    x = 0
    for _, width, fmt in columns:
        if x >= max_x:
            break
        try:
            cell = fmt(row)[:width].ljust(width)
        except Exception:
            cell = "?".ljust(width)
        avail = max_x - x
        stdscr.attron(attr)
        stdscr.addstr(y, x, cell[:avail])
        stdscr.attroff(attr)
        x += width + 1

def tui_main(stdscr, store: FlowStore, args, stop_event: threading.Event):
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()

    curses.init_pair(1, curses.COLOR_GREEN,   -1)  # ESTABLISHED
    curses.init_pair(2, curses.COLOR_BLUE,    -1)  # LISTEN
    curses.init_pair(3, curses.COLOR_CYAN,    -1)  # SYN_*
    curses.init_pair(4, curses.COLOR_YELLOW,  -1)  # FIN_* / TIME_WAIT
    curses.init_pair(5, curses.COLOR_RED,     -1)  # CLOSE / LAST_ACK
    curses.init_pair(6, curses.COLOR_BLACK,   curses.COLOR_WHITE)  # status bar

    sort_fn      = SORT_KEYS.get(args.sort_by, SORT_KEYS["pkts"])
    state_filter = _parse_state_filter(args.state_filter)
    columns      = build_columns(args.verbose)
    scroll_top   = 0
    cursor_row   = 0

    while not stop_event.is_set():
        # ── Teclado ───────────────────────────────────────────────────────
        try:
            ch = stdscr.getch()
        except Exception:
            ch = -1

        if ch in (ord('q'), ord('Q'), 27):
            stop_event.set()
            break
        elif ch == curses.KEY_UP:
            cursor_row  = max(0, cursor_row - 1)
            scroll_top  = min(scroll_top, cursor_row)
        elif ch == curses.KEY_DOWN:
            cursor_row += 1
        elif ch == curses.KEY_PPAGE:   # Page Up
            cursor_row  = max(0, cursor_row - 10)
            scroll_top  = max(0, scroll_top - 10)
        elif ch == curses.KEY_NPAGE:   # Page Down
            cursor_row += 10

        rows         = store.snapshot(sort_key=sort_fn, state_filter=state_filter)
        max_y, max_x = stdscr.getmaxyx()
        data_rows    = max_y - 3   # linhas disponíveis para dados

        # Ajusta scroll para manter cursor visível
        cursor_row = min(cursor_row, max(0, len(rows) - 1))
        if cursor_row < scroll_top:
            scroll_top = cursor_row
        elif cursor_row >= scroll_top + data_rows:
            scroll_top = cursor_row - data_rows + 1

        stdscr.erase()

        # ── Barra de status (linha 0) ─────────────────────────────────────
        established = sum(1 for r in rows if r["state"] == "ESTABLISHED")
        status = (
            f" TCP Monitor │ {time.strftime('%H:%M:%S')} │ "
            f"total={len(rows)}  ESTABLISHED={established} │ "
            f"sort={args.sort_by} │ ttl={args.ttl:.0f}s │ q:sair ↑↓:navegar"
        )
        stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
        stdscr.addstr(0, 0, status[:max_x].ljust(max_x))
        stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)

        # ── Cabeçalho da tabela (linha 1) ─────────────────────────────────
        draw_header(stdscr, 1, columns, max_x)

        # ── Linhas de dados ───────────────────────────────────────────────
        visible = rows[scroll_top: scroll_top + data_rows]
        for idx, row in enumerate(visible):
            y          = idx + 2
            abs_idx    = scroll_top + idx
            highlight  = (abs_idx == cursor_row)
            draw_row(stdscr, y, row, columns, max_x, highlight)

        # Preenche linhas vazias (após os dados) para limpar resíduos
        for y in range(len(visible) + 2, max_y - 1):
            stdscr.addstr(y, 0, " " * (max_x - 1))

        # ── Rodapé (última linha) ─────────────────────────────────────────
        if rows:
            end_row = min(scroll_top + data_rows, len(rows))
            footer  = f" linhas {scroll_top + 1}–{end_row} de {len(rows)}"
        else:
            footer  = " Aguardando fluxos TCP..."
        stdscr.attron(curses.A_DIM)
        stdscr.addstr(max_y - 1, 0, footer[:max_x - 1].ljust(max_x - 1))
        stdscr.attroff(curses.A_DIM)

        stdscr.refresh()
        time.sleep(args.display_interval)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_state_filter(raw):
    if not raw:
        return None
    inv    = {v: k for k, v in TCP_STATES.items()}
    result = set()
    for s in raw.upper().split(","):
        s = s.strip()
        if s in inv:
            result.add(inv[s])
        else:
            print(f"[warn] Estado desconhecido no filtro: '{s}'", file=sys.stderr)
    return result or None

# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Monitor de fluxos TCP via eBPF (TUI)")
    p.add_argument("--bpf-src",          default=BPF_SOURCE,
                   help="Arquivo fonte BPF (padrão: tcp_stats_sockkey.c)")
    p.add_argument("--collect-interval", type=float, default=0.3,
                   help="Intervalo de coleta do mapa BPF em segundos (padrão: 0.3)")
    p.add_argument("--display-interval", type=float, default=0.5,
                   help="Intervalo de refresh da TUI em segundos (padrão: 0.5)")
    p.add_argument("--ttl",              type=float, default=30.0,
                   help="Segundos de inatividade para remover entrada (padrão: 30)")
    p.add_argument("--state-filter",     default=None,
                   help="Filtrar estados TCP, ex: ESTABLISHED,SYN_SENT")
    p.add_argument("--sort-by",          default="pkts",
                   choices=list(SORT_KEYS),
                   help="Coluna de ordenação: pkts|bytes|rtt|retr|state (padrão: pkts)")
    p.add_argument("--verbose", "-v",    action="store_true",
                   help="Exibir sock_ptr e cc_ptr")
    return p.parse_args()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # Suprime warnings de compilação BPF (redefinição de macros __HAVE_BUILTIN_BSWAPxx__)
    devnull = open(os.devnull, "w")
    old_fd  = os.dup(2)
    os.dup2(devnull.fileno(), 2)
    try:
        from bcc import BPF
        b = BPF(src_file=args.bpf_src)
    except Exception as e:
        os.dup2(old_fd, 2)
        print(f"Erro ao compilar/carregar BPF: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        os.dup2(old_fd, 2)
        os.close(old_fd)
        devnull.close()

    try:
        table = b.get_table("flow_stats")
    except Exception as e:
        print(f"Erro ao abrir tabela flow_stats: {e}", file=sys.stderr)
        sys.exit(1)

    resolver   = KallsymsResolver()
    store      = FlowStore(ttl_s=args.ttl)
    stop_event = threading.Event()

    t_collect = threading.Thread(
        target=collector_thread,
        args=(table, resolver, store, args.collect_interval, stop_event),
        daemon=True,
        name="collector",
    )
    t_collect.start()

    try:
        curses.wrapper(tui_main, store, args, stop_event)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        t_collect.join(timeout=2)
        print("Monitor encerrado.")

if __name__ == "__main__":
    main()
