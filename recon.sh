#!/bin/bash

# ============================================================
#   RECON.SH — Master Recon Pipeline
#   Pipeline: subfinder → targets.txt → bypass.sh → log
#
#   Uso: ./recon.sh
#        ./recon.sh -d target.com
#        ./recon.sh -d target.com -o results.txt
#
#   Dipendenze: subfinder, bypass.sh (nella stessa directory
#               o in $PATH), curl
# ============================================================

# ---------- Colori ANSI ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ---------- Valori di default ----------
TARGETS_FILE="targets.txt"
LOG_FILE=""          # vuoto = bypass.sh usa il suo default (waf_scan_results.txt)
DOMAIN=""
BYPASS_SCRIPT=""     # verrà risolto in fase di pre-flight

# ---------- Banner ----------
print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${RESET}${DIM}  Master Recon Pipeline — subfinder + WAF Scanner${RESET}"
    echo ""
}

# ---------- Helper: stampa step numerati ----------
step() {
    local num="$1"
    local msg="$2"
    echo -e "${BOLD}${MAGENTA}[STEP ${num}]${RESET} ${msg}"
}

ok()   { echo -e "  ${GREEN}[✔]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "  ${RED}[✘]${RESET} $*"; }
info() { echo -e "  ${CYAN}[*]${RESET} $*"; }

divider() {
    echo -e "${DIM}  ──────────────────────────────────────────────────${RESET}"
}

# ---------- Uso / help ----------
usage() {
    echo -e "${BOLD}Uso:${RESET}"
    echo "  ./recon.sh                        # modalità interattiva"
    echo "  ./recon.sh -d target.com          # dominio da argomento"
    echo "  ./recon.sh -d target.com -o log   # log personalizzato"
    echo ""
    echo -e "${BOLD}Opzioni:${RESET}"
    echo "  -d  Dominio bersaglio (es: example.com)"
    echo "  -o  File di output per il log WAF (default: waf_scan_results.txt)"
    echo "  -h  Mostra questo messaggio"
    exit 0
}

# ---------- Parsing argomenti ----------
while getopts ":d:o:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        o) LOG_FILE="$OPTARG" ;;
        h) usage ;;
        :) err "Opzione -${OPTARG} richiede un argomento."; exit 1 ;;
        \?) err "Opzione non valida: -${OPTARG}"; exit 1 ;;
    esac
done

# ============================================================
# PRE-FLIGHT: verifica dipendenze prima di fare qualsiasi cosa
# ============================================================
preflight_checks() {
    step "0" "Pre-flight — verifica dipendenze"
    divider
    local fail=false

    # 1. Controlla subfinder
    if command -v subfinder &>/dev/null; then
        ok "subfinder trovato: $(command -v subfinder)"
    else
        err "subfinder NON trovato nel PATH."
        echo -e "     ${DIM}Installalo con: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${RESET}"
        echo -e "     ${DIM}Oppure: https://github.com/projectdiscovery/subfinder/releases${RESET}"
        fail=true
    fi

    # 2. Controlla bypass.sh (prima nella stessa dir dello script, poi nel PATH)
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "${script_dir}/bypass.sh" ]]; then
        BYPASS_SCRIPT="${script_dir}/bypass.sh"
        ok "bypass.sh trovato: ${BYPASS_SCRIPT}"
        # Assicurati che sia eseguibile
        chmod +x "$BYPASS_SCRIPT" 2>/dev/null
    elif command -v bypass.sh &>/dev/null; then
        BYPASS_SCRIPT="$(command -v bypass.sh)"
        ok "bypass.sh trovato nel PATH: ${BYPASS_SCRIPT}"
    else
        err "bypass.sh NON trovato."
        echo -e "     ${DIM}Metti bypass.sh nella stessa directory di recon.sh oppure nel PATH.${RESET}"
        fail=true
    fi

    # 3. Controlla curl (serve a bypass.sh)
    if command -v curl &>/dev/null; then
        ok "curl trovato: $(command -v curl)"
    else
        err "curl NON trovato nel PATH."
        fail=true
    fi

    divider
    if $fail; then
        err "Pre-flight fallito. Installa le dipendenze mancanti e riprova."
        exit 1
    fi

    ok "Tutte le dipendenze soddisfatte."
    echo ""
}

# ============================================================
# STEP 1 — Acquisizione del dominio
# ============================================================
acquire_domain() {
    step "1" "Dominio bersaglio"
    divider

    # Se non passato via -d, chiedi interattivamente
    if [[ -z "$DOMAIN" ]]; then
        echo -ne "  ${BOLD}Inserisci il dominio bersaglio${RESET} (es: example.com): "
        read -r DOMAIN
    else
        info "Dominio ricevuto da argomento: ${BOLD}${DOMAIN}${RESET}"
    fi

    # Pulizia: rimuovi eventuale http(s):// e slash finale
    DOMAIN="${DOMAIN#http://}"
    DOMAIN="${DOMAIN#https://}"
    DOMAIN="${DOMAIN%%/*}"
    DOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]' | xargs)

    # Validazione minima: deve contenere almeno un punto
    if [[ -z "$DOMAIN" ]] || ! echo "$DOMAIN" | grep -qE "^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$"; then
        err "Dominio non valido: '${DOMAIN}'"
        exit 1
    fi

    ok "Dominio validato: ${BOLD}${CYAN}${DOMAIN}${RESET}"
    echo ""
}

# ============================================================
# STEP 2 — Enumerazione sottodomini con subfinder
# ============================================================
run_subfinder() {
    step "2" "Enumerazione sottodomini con subfinder"
    divider
    info "Dominio    : ${BOLD}${DOMAIN}${RESET}"
    info "Output file: ${BOLD}${TARGETS_FILE}${RESET}"
    info "Avvio subfinder... (potrebbe richiedere qualche minuto)"
    echo ""

    # Aggiunge https:// ai sottodomini trovati così bypass.sh può usarli direttamente con curl
    subfinder -d "$DOMAIN" -silent 2>/dev/null | while IFS= read -r sub; do
        echo "https://${sub}"
    done > "$TARGETS_FILE"

    local exit_code=${PIPESTATUS[0]}

    # subfinder può restituire 0 anche senza risultati; controlliamo separatamente
    if [[ $exit_code -ne 0 ]]; then
        warn "subfinder ha restituito un codice di errore (${exit_code})."
        warn "Potrebbe trattarsi di un problema di rete o di configurazione API."
    fi

    echo ""
}

# ============================================================
# STEP 3 — Verifica risultati subfinder
# ============================================================
check_targets() {
    step "3" "Verifica file target"
    divider

    if [[ ! -f "$TARGETS_FILE" ]]; then
        err "Il file '${TARGETS_FILE}' non è stato creato."
        exit 1
    fi

    # Conta le righe valide (non vuote)
    local count
    count=$(grep -cE "^https?://" "$TARGETS_FILE" 2>/dev/null || echo 0)

    if [[ "$count" -eq 0 ]]; then
        warn "Nessun sottodominio trovato per '${DOMAIN}'."
        warn "Possibili cause:"
        echo -e "  ${DIM}  • Il dominio non ha sottodomini pubblici indicizzati${RESET}"
        echo -e "  ${DIM}  • subfinder richiede chiavi API per alcune fonti (config: ~/.config/subfinder/provider-config.yaml)${RESET}"
        echo -e "  ${DIM}  • Problema di connessione di rete${RESET}"
        exit 0
    fi

    ok "Sottodomini trovati: ${BOLD}${GREEN}${count}${RESET}"
    echo ""

    # Mostra anteprima dei primi 10
    info "Anteprima (primi 10):"
    head -n 10 "$TARGETS_FILE" | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${RESET}"
    done
    [[ "$count" -gt 10 ]] && echo -e "    ${DIM}... e altri $((count - 10)) sottodomini${RESET}"
    echo ""
}

# ============================================================
# STEP 4 — Lancio bypass.sh sulla lista generata
# ============================================================
run_bypass() {
    step "4" "Avvio WAF Scanner (bypass.sh)"
    divider

    # Costruisce il comando con o senza log file personalizzato
    local cmd=("$BYPASS_SCRIPT" "$TARGETS_FILE")
    [[ -n "$LOG_FILE" ]] && cmd+=("$LOG_FILE")

    info "Comando: ${BOLD}${cmd[*]}${RESET}"
    echo ""
    divider
    echo ""

    # Esegui bypass.sh; eredita stdout/stderr così l'output è visibile in tempo reale
    "${cmd[@]}"
    local exit_code=$?

    echo ""
    divider

    if [[ $exit_code -eq 0 ]]; then
        ok "bypass.sh completato con successo."
    else
        warn "bypass.sh è terminato con codice ${exit_code}."
    fi
    echo ""
}

# ============================================================
# RIEPILOGO FINALE
# ============================================================
print_summary() {
    local log_actual="${LOG_FILE:-waf_scan_results.txt}"
    echo -e "${BOLD}${CYAN}  ══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}    PIPELINE COMPLETATA${RESET}"
    echo -e "${CYAN}  ══════════════════════════════════════════════════${RESET}"
    echo -e "  ${DIM}Dominio scansionato :${RESET} ${BOLD}${DOMAIN}${RESET}"
    echo -e "  ${DIM}Sottodomini trovati :${RESET} ${BOLD}$(grep -c "." "$TARGETS_FILE" 2>/dev/null || echo 0)${RESET}"
    echo -e "  ${DIM}File target         :${RESET} ${BOLD}${TARGETS_FILE}${RESET}"
    echo -e "  ${DIM}Log WAF             :${RESET} ${BOLD}${log_actual}${RESET}"
    echo -e "${CYAN}  ══════════════════════════════════════════════════${RESET}"
    echo ""
}

# ============================================================
# MAIN — Orchestrazione della pipeline
# ============================================================
main() {
    print_banner
    preflight_checks
    acquire_domain
    run_subfinder
    check_targets
    run_bypass
    print_summary
}

main