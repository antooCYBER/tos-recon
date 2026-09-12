#!/bin/bash

# ============================================================
#   ADVANCED RECON & WAF MASS SCANNER
#   Uso: ./bypass.sh targets.txt [output_log.txt]
# ============================================================

BANNER="=== ADVANCED RECON & WAF MASS SCANNER ==="
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
TIMEOUT=10

# ---------- Colori ANSI ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------- Argomenti ----------
INPUT_FILE="$1"
LOG_FILE="${2:-waf_scan_results.txt}"

echo -e "${BOLD}${CYAN}${BANNER}${RESET}"

# Verifica che il file input sia stato passato
if [[ -z "$INPUT_FILE" ]]; then
    echo -e "${RED}[ERRORE]${RESET} Nessun file specificato."
    echo -e "  Uso: ${BOLD}./bypass.sh targets.txt [output_log.txt]${RESET}"
    exit 1
fi

# Verifica che il file esista e non sia vuoto
if [[ ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}[ERRORE]${RESET} File '${INPUT_FILE}' non trovato."
    exit 1
fi

if [[ ! -s "$INPUT_FILE" ]]; then
    echo -e "${RED}[ERRORE]${RESET} File '${INPUT_FILE}' è vuoto."
    exit 1
fi

# Conta le righe valide (non vuote, non commenti)
TOTAL=$(grep -cE "^[^#[:space:]]" "$INPUT_FILE" 2>/dev/null || echo 0)
echo -e "[*] File di input : ${BOLD}${INPUT_FILE}${RESET}"
echo -e "[*] Log di output : ${BOLD}${LOG_FILE}${RESET}"
echo -e "[*] Target trovati: ${BOLD}${TOTAL}${RESET}"
echo ""

# Inizializza il file di log
{
    echo "======================================================"
    echo "  ADVANCED RECON & WAF MASS SCANNER - Log"
    echo "  Data/Ora: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Input   : ${INPUT_FILE}"
    echo "  Target  : ${TOTAL}"
    echo "======================================================"
    echo ""
} > "$LOG_FILE"

# ---------- Contatori riassuntivi ----------
COUNT_OK=0
COUNT_BLOCKED=0
COUNT_WAF=0
COUNT_ERROR=0
INDEX=0

# ---------- Funzione di analisi singolo target ----------
scan_target() {
    local target="$1"
    local tmp_headers
    tmp_headers=$(mktemp)

    # Esegui curl con timeout e salva gli header
    curl -s -I \
        --max-time "$TIMEOUT" \
        --connect-timeout "$TIMEOUT" \
        -A "$USER_AGENT" \
        -H "Accept-Language: it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
        "$target" > "$tmp_headers" 2>/dev/null

    local curl_exit=$?
    local status
    status=$(head -n 1 "$tmp_headers" | tr -d '\r')
    local http_code
    http_code=$(echo "$status" | grep -oE "[0-9]{3}" | head -n1)

    local result_label=""
    local result_detail=""

    # Errore di connessione (curl fallito)
    if [[ $curl_exit -ne 0 ]] || [[ -z "$status" ]]; then
        result_label="ERRORE"
        result_detail="Nessuna risposta (timeout o host non raggiungibile)"
        echo -e "  ${RED}[ERRORE]${RESET}  ${target}"
        echo -e "           └─ ${result_detail}"
        COUNT_ERROR=$((COUNT_ERROR + 1))
        rm -f "$tmp_headers"
        echo "[$result_label] $target — $result_detail" >> "$LOG_FILE"
        return
    fi

    # Rilevamento WAF
    local waf_detected=""
    if grep -qi "cloudflare" "$tmp_headers" || grep -qi "cf-ray" "$tmp_headers" || grep -qi "Just a moment" "$tmp_headers"; then
        waf_detected="CLOUDFLARE"
    elif grep -qi "datadome" "$tmp_headers"; then
        waf_detected="DATADOME (Anti-Bot Avanzato)"
    elif grep -qi "akamai" "$tmp_headers" || grep -qi "x-akamai" "$tmp_headers"; then
        waf_detected="AKAMAI"
    elif grep -qi "imperva" "$tmp_headers" || grep -qi "incapsula" "$tmp_headers"; then
        waf_detected="IMPERVA / INCAPSULA"
    elif grep -qi "sucuri" "$tmp_headers"; then
        waf_detected="SUCURI"
    elif grep -qi "x-sucuri-id" "$tmp_headers"; then
        waf_detected="SUCURI"
    elif grep -qi "aws-waf" "$tmp_headers" || grep -qi "x-amzn-waf" "$tmp_headers"; then
        waf_detected="AWS WAF"
    fi

    # Valutazione codice HTTP
    local blocked=false
    if echo "$http_code" | grep -qE "^(403|401|503|429)$"; then
        blocked=true
    fi

    # Composizione risultato
    if [[ -n "$waf_detected" ]] && $blocked; then
        result_label="WAF+BLOCK"
        result_detail="HTTP $http_code — WAF: $waf_detected — Accesso bloccato"
        echo -e "  ${RED}[WAF+BLOCK]${RESET} ${target}"
        echo -e "           └─ HTTP ${http_code} | WAF: ${YELLOW}${waf_detected}${RESET}"
        COUNT_WAF=$((COUNT_WAF + 1))
        COUNT_BLOCKED=$((COUNT_BLOCKED + 1))
    elif [[ -n "$waf_detected" ]]; then
        result_label="WAF"
        result_detail="HTTP $http_code — WAF rilevato: $waf_detected"
        echo -e "  ${YELLOW}[WAF]${RESET}      ${target}"
        echo -e "           └─ HTTP ${http_code} | WAF: ${YELLOW}${waf_detected}${RESET}"
        COUNT_WAF=$((COUNT_WAF + 1))
    elif $blocked; then
        result_label="BLOCCATO"
        result_detail="HTTP $http_code — Accesso negato (nessun WAF identificato)"
        echo -e "  ${YELLOW}[BLOCCATO]${RESET} ${target}"
        echo -e "           └─ HTTP ${http_code} — Accesso negato"
        COUNT_BLOCKED=$((COUNT_BLOCKED + 1))
    else
        result_label="OK"
        result_detail="HTTP $http_code — Nessun blocco o WAF rilevato"
        echo -e "  ${GREEN}[OK]${RESET}       ${target}"
        echo -e "           └─ HTTP ${http_code} — Nessun WAF aggressivo rilevato"
        COUNT_OK=$((COUNT_OK + 1))
    fi

    rm -f "$tmp_headers"

    # Scrittura nel log
    {
        echo "[$result_label] $target"
        echo "         $result_detail"
        echo ""
    } >> "$LOG_FILE"
}

# ---------- Loop principale ----------
while IFS= read -r line || [[ -n "$line" ]]; do
    # Salta righe vuote e commenti
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    # Rimuovi spazi iniziali/finali
    line=$(echo "$line" | xargs)
    [[ -z "$line" ]] && continue

    INDEX=$((INDEX + 1))
    echo -e "${BOLD}[${INDEX}/${TOTAL}]${RESET} Scansione: ${CYAN}${line}${RESET}"
    scan_target "$line"
    echo ""

done < "$INPUT_FILE"

# ---------- Riepilogo finale ----------
DIVIDER="======================================================"
echo -e "${BOLD}${CYAN}${DIVIDER}${RESET}"
echo -e "${BOLD}  RIEPILOGO SCANSIONE${RESET}"
echo -e "${DIVIDER}"
echo -e "  ${GREEN}[OK]       Puliti    : ${COUNT_OK}${RESET}"
echo -e "  ${YELLOW}[WAF]      Con WAF   : ${COUNT_WAF}${RESET}"
echo -e "  ${YELLOW}[BLOCCATO] Bloccati  : ${COUNT_BLOCKED}${RESET}"
echo -e "  ${RED}[ERRORE]   Errori    : ${COUNT_ERROR}${RESET}"
echo -e "  Totale scansionati  : ${INDEX}"
echo -e "${DIVIDER}"
echo -e "  Log completo salvato in: ${BOLD}${LOG_FILE}${RESET}"
echo -e "${CYAN}${DIVIDER}${RESET}"

# Aggiungi riepilogo al log
{
    echo ""
    echo "======================================================"
    echo "  RIEPILOGO FINALE"
    echo "======================================================"
    echo "  OK (puliti)   : $COUNT_OK"
    echo "  Con WAF       : $COUNT_WAF"
    echo "  Bloccati      : $COUNT_BLOCKED"
    echo "  Errori        : $COUNT_ERROR"
    echo "  Totale        : $INDEX"
    echo "  Completato    : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "======================================================"
} >> "$LOG_FILE"