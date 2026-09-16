#!/bin/sh
# Veritas AC 1.3 — portable Linux + macOS terminal audit helper
# POSIX /bin/sh core. Optional platform-specific tools are detected at runtime.
# Use only on systems/accounts you are authorized to inspect.

set +e
umask 077

APP_NAME="Veritas AC"
VERSION="1.3"
LANGUAGE=${VERITAS_LANG:-uk}
BASE_DIR=${PWD:-.}
REPORT_DIR="$BASE_DIR/veritas_ac_reports"
MOD_BASELINE="$BASE_DIR/veritas_ac_mod_baseline.sha256"

# ---------- basic compatibility helpers ----------

have() {
  command -v "$1" >/dev/null 2>&1
}

say_skip() {
  printf '[SKIP] %s\n' "$1"
}

mkdir -p "$REPORT_DIR" 2>/dev/null || {
  REPORT_DIR="${TMPDIR:-/tmp}/veritas_ac_reports"
  mkdir -p "$REPORT_DIR" 2>/dev/null || exit 1
}

OS=$(uname -s 2>/dev/null)
case "$OS" in
  Linux) PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *) PLATFORM="unknown" ;;
esac

STAMP=$(date '+%Y-%m-%d_%H-%M-%S' 2>/dev/null)
[ -n "$STAMP" ] || STAMP="scan_$$"
REPORT="$REPORT_DIR/veritas_ac_${STAMP}.txt"

TMPBASE=${TMPDIR:-/tmp}
if [ ! -d "$TMPBASE" ] || [ ! -w "$TMPBASE" ]; then
  TMPBASE=/tmp
fi

BANNED_PATTERN='akrien|ares|aristois|armor[ _-]*hotswap|arbuz|atomic|autoattack|aimbot|autoclicky|bariton|bedrock[ _-]*breaker[ _-]*mode|bleachhack|calestial|celestial|celka|chunk[ _-]*copy|clean[ _-]*cut|clientcommands|clickcrystals|crystal[ _-]*optimizer|camerautils|chest|cutthrough|dauntiblyat|deadcode|delta|diamond[ _-]*sim|doomsday|double[ _-]*hotbar|dreampool|eclipse|elytra[ _-]*swap|elytra[ _-]*hack|entity[ _-]*outliner|entity[ _-]*xray|expensive|exire|extazyy|feather[ _-]*client|forge[ _-]*hax|freecam|future|fuzeclient|hakari|hush|huzuni|hach|impact|infinity|inertia|invmove|inventory[ _-]*walk|inventory[ _-]*profiles[ _-]*next|invtweaks|inventorysorter|jex|konas|librarian[ _-]*trade[ _-]*finder|liquidbounce|lowdurabilityswitcher|luminex|meteor|minced|mobhitbox|moonhack|neverhook|nightware|nodus|nova|nurik|nursultan|nemo.?s[ _-]*inventory|nuclear|ricardo|richclient|rogalik|rusherhack|sacurachorusfind|save[ _-]*searcher|seed[ _-]*cracker|sigma|skill[ _-]*client|smart[ _-]*moving|squad|step[ _-]*up|swingthroughgrass|takker|thunderhack|topkaautobuy|troxill|tweakeroo|topkaautodrop|tool[ _-]*swap|vape|vec\.dll|venus|viaforge|viabackwards|viaproxy|wurst|wildclient|winner|worlddownloader|wexside|wissend|xray|zamorozka|zeusclient|zenithclient'

BANNED_NORMALIZED='akrien|ares|aristois|armorhotswap|arbuz|atomic|autoattack|aimbot|autoclicky|bariton|bedrockbreakermode|bleachhack|calestial|celestial|celka|chunkcopy|cleancut|clientcommands|clickcrystals|crystaloptimizer|camerautils|chest|cutthrough|dauntiblyat|deadcode|delta|diamondsim|doomsday|doublehotbar|dreampool|eclipse|elytraswap|elytrahack|entityoutliner|entityxray|expensive|exire|extazyy|featherclient|forgehax|freecam|future|fuzeclient|hakari|hush|huzuni|hach|impact|infinity|inertia|invmove|inventorywalk|inventoryprofilesnext|invtweaks|inventorysorter|jex|konas|librariantradefinder|liquidbounce|lowdurabilityswitcher|luminex|meteor|minced|mobhitbox|moonhack|neverhook|nightware|nodus|nova|nurik|nursultan|nemosinventory|nuclear|ricardo|richclient|rogalik|rusherhack|sacurachorusfind|savesearcher|seedcracker|sigma|skillclient|smartmoving|squad|stepup|swingthroughgrass|takker|thunderhack|topkaautobuy|troxill|tweakeroo|topkaautodrop|toolswap|vape|vecdll|venus|viaforge|viabackwards|viaproxy|wurst|wildclient|winner|worlddownloader|wexside|wissend|xray|zamorozka|zeusclient|zenithclient'


# Text-content matching is intentionally stricter than archive filename matching.
# STRONG terms are distinctive enough to search in ordinary configs/logs.
CONTENT_STRONG_PATTERN='akrien|aristois|armor[ _.-]*hotswap|arbuz|autoattack|aimbot|autoclicky|bariton|bedrock[ _.-]*breaker[ _.-]*mode|bleachhack|calestial|celka|chunk[ _.-]*copy|clientcommands|clickcrystals|crystal[ _.-]*optimizer|camerautils|cutthrough|dauntiblyat|diamond[ _.-]*sim|double[ _.-]*hotbar|dreampool|elytra[ _.-]*swap|elytra[ _.-]*hack|entity[ _.-]*outliner|entity[ _.-]*xray|exire|extazyy|feather[ _.-]*client|forge[ _.-]*hax|freecam|fuze[ _.-]*client|huzuni|invmove|inventory[ _.-]*walk|inventory[ _.-]*profiles[ _.-]*next|invtweaks|inventorysorter|jex|konas|librarian[ _.-]*trade[ _.-]*finder|liquidbounce|lowdurabilityswitcher|luminex|minced|mobhitbox|moonhack|neverhook|nightware|nodus|nurik|nursultan|nemo.?s[ _.-]*inventory|richclient|rogalik|rusherhack|sacurachorusfind|save[ _.-]*searcher|seed[ _.-]*cracker|sigma|skill[ _.-]*client|smart[ _.-]*moving|step[ _.-]*up|swingthroughgrass|takker|thunderhack|topkaautobuy|troxill|tweakeroo|topkaautodrop|tool[ _.-]*swap|vape|vec[._-]*dll|venus|viaforge|viabackwards|viaproxy|wurst|wildclient|worlddownloader|wexside|wissend|xray|zamorozka|zeusclient|zenithclient'

# WEAK terms are real names/modules in the supplied list but are also common
# words, names or programming identifiers. They are only searched in known
# Minecraft/launcher locations and only as whole tokens.
CONTENT_WEAK_PATTERN='ares|atomic|celestial|chest|cleancut|deadcode|delta|doomsday|eclipse|expensive|future|hach|hakari|hush|impact|infinity|inertia|meteor|nova|nuclear|ricardo|squad|winner'

# Archive payloads contain compressed binary data, where short words can occur
# by chance.  This deliberately narrow set is used only for archive entries
# and raw strings; generic modules such as "freecam" or "xray" are not enough.
ARCHIVE_SIGNATURE_PATTERN='akrien|aristois|armor[ _./-]*hotswap|bleachhack|calestial|clickcrystals|crystal[ _./-]*optimizer|dauntiblyat|dreampool|elytra[ _./-]*hack|elytra[ _./-]*swap|expensive|extazyy|feather[ _./-]*client|forge[ _./-]*hax|fuzeclient|hakari|huzuni|impactclient|inertiamod|liquidbounce|meteorclient|meteordevelopment|moonhack|neverhook|nightware|nursultan|richclient|rogalik|rusherhack|seed[ _./-]*cracker|skill[ _./-]*client|thunderhack|troxill|vape[ _./-]*client|viaforge|viaproxy|wurstclient|wildclient|wexside|wissend|zamorozka|zeusclient|zenithclient'

content_re() {
  # Portable ERE boundary: do not use GNU-only \b, \< or \>.
  printf '(^|[^[:alnum:]])(%s)([^[:alnum:]]|$)' "$1"
}

is_minecraft_related_path() {
  p=$1
  case "$p" in
    "$HOME/.minecraft"/*|\
    "$HOME/.local/share/PrismLauncher"/*|\
    "$HOME/.local/share/PolyMC"/*|\
    "$HOME/.local/share/multimc"/*|\
    "$HOME/.local/share/ModrinthApp"/*|\
    "$HOME/.local/share/modrinthapp"/*|\
    "$HOME/.config/ATLauncher"/*|\
    "$HOME/.config/GDLauncher"/*|\
    "$HOME/.config/feather"/*|\
    "$HOME/Library/Application Support/minecraft"/*|\
    "$HOME/Library/Application Support/PrismLauncher"/*|\
    "$HOME/Library/Application Support/PolyMC"/*|\
    "$HOME/Library/Application Support/MultiMC"/*|\
    "$HOME/Library/Application Support/ModrinthApp"/*|\
    "$HOME/Library/Application Support/ATLauncher"/*|\
    "$HOME/Library/Application Support/GDLauncher"/*|\
    "$HOME/Library/Application Support/Feather"/*)
      return 0
      ;;
  esac

  # Covers launcher forks found dynamically in common per-user application
  # locations, without treating arbitrary documents as Minecraft data.
  case "$p" in
    "$HOME/.local/share/"*|"$HOME/.config/"*|"$HOME/.var/app/"*|"$HOME/snap/"*|\
    "$HOME/Library/Application Support/"*|"$HOME/Library/Containers/"*)
      lower_path=$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')
      case "$lower_path" in
        *minecraft*|*launcher*|*multimc*|*polymc*|*modrinth*|*curseforge*|\
        *technic*|*atlauncher*|*gdlauncher*|*feedthebeast*|\
        */feather/*|*/featherclient/*|*/feather-client/*) return 0 ;;
      esac
      ;;
  esac
  return 1
}

is_reference_list_file() {
  f=$1
  [ -r "$f" ] || return 1
  # Prevent the checker/manual/source code containing its own detection list
  # from reporting itself as dozens of cheat hits.
  grep -qE 'BANNED_(NORMALIZED|PATTERN)=|CONTENT_(STRONG|WEAK)_PATTERN=|PATTERN=.akrien\|ares\|aristois' "$f" 2>/dev/null
}

if [ -t 1 ]; then
  c_reset=$(printf '\033[0m')
  c_bold=$(printf '\033[1m')
  c_cyan=$(printf '\033[36m')
  c_yellow=$(printf '\033[33m')
  c_green=$(printf '\033[32m')
  c_red=$(printf '\033[31m')
  c_blue=$(printf '\033[34m')
  c_magenta=$(printf '\033[35m')
  c_dim=$(printf '\033[2m')
else
  c_reset=''
  c_bold=''
  c_cyan=''
  c_yellow=''
  c_green=''
  c_red=''
  c_blue=''
  c_magenta=''
  c_dim=''
fi

ui_title() {
  printf '%s%s╭──────────────────────────────────────────────────────────────╮%s\n' "$c_cyan" "$c_bold" "$c_reset"
  printf '%s%s│  Veritas AC  ·  Linux/macOS audit console                  │%s\n' "$c_cyan" "$c_bold" "$c_reset"
  printf '%s%s╰──────────────────────────────────────────────────────────────╯%s\n' "$c_cyan" "$c_bold" "$c_reset"
}

ui_progress() {
  # Compact progress marker that works in plain pipes and old terminals.
  printf '%s→%s %s\n' "$c_blue" "$c_reset" "$1"
}

ui_result_hint() {
  case "$1" in
    *'[CONTENT]'*|*'[NAME]'*) printf '%s%s%s\n' "$c_red" "$1" "$c_reset" ;;
    *'[SKIP'*|*'[MISS]'*) printf '%s%s%s\n' "$c_yellow" "$1" "$c_reset" ;;
    *'[OK]'*|*'completed'*|*'Готово'*) printf '%s%s%s\n' "$c_green" "$1" "$c_reset" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

hr() {
  printf '%s\n' '------------------------------------------------------------'
}

pause_menu() {
  case "$LANGUAGE" in
    ru) printf '\nНажми Enter, чтобы продолжить...' ;;
    en) printf '\nPress Enter to continue...' ;;
    *)  printf '\nНатисни Enter, щоб продовжити...' ;;
  esac
  IFS= read -r _unused
}

clear_screen() {
  if [ -t 1 ] && [ -n "${TERM:-}" ] && have clear; then
    clear
  else
    printf '\n\n'
  fi
}

log_section() {
  printf '\n===== %s =====\n' "$1" >> "$REPORT"
}

# tee is POSIX, but keep a fallback for extremely minimal environments.
outlog() {
  if have tee; then
    tee -a "$REPORT"
  else
    cat >> "$REPORT"
  fi
}

safe_head() {
  n=$1
  if have head; then
    head -n "$n"
  else
    cat
  fi
}

safe_tail() {
  n=$1
  if have tail; then
    tail -n "$n"
  else
    cat
  fi
}

# Temporary files can contain usernames, paths and process information.  Use a
# private directory created atomically rather than predictable /tmp filenames.
make_private_tmpdir() {
  if ! have mktemp; then
    say_skip "mktemp unavailable; this check requires a secure temporary directory" >&2
    return 1
  fi
  mktemp -d "$TMPBASE/veritas_ac.XXXXXX" 2>/dev/null
}

header() {
  clear_screen
  ui_title
  case "$LANGUAGE" in
    ru)
      printf '%sВерсия:%s %-12s %sПлатформа:%s %-8s %sПользователь:%s %s\n' "$c_dim" "$c_reset" "$VERSION" "$c_dim" "$c_reset" "$PLATFORM" "$c_dim" "$c_reset" "${USER:-unknown}"
      printf '%sОтчёт:%s %s\n' "$c_dim" "$c_reset" "$REPORT"
      printf '%sВажно:%s совпадения — сигналы для ручной проверки, не автоматическое доказательство.\n' "$c_yellow" "$c_reset"
      printf '%sГраница защиты:%s локальный скрипт не гарантирует защиту от обхода; нужна серверная проверка.\n' "$c_yellow" "$c_reset"
      ;;
    en)
      printf '%sVersion:%s %-12s %sPlatform:%s %-8s %sUser:%s %s\n' "$c_dim" "$c_reset" "$VERSION" "$c_dim" "$c_reset" "$PLATFORM" "$c_dim" "$c_reset" "${USER:-unknown}"
      printf '%sReport:%s %s\n' "$c_dim" "$c_reset" "$REPORT"
      printf '%sNotice:%s matches are leads for manual review, not automatic proof.\n' "$c_yellow" "$c_reset"
      printf '%sProtection boundary:%s a local script cannot prevent bypass; server-side verification is required.\n' "$c_yellow" "$c_reset"
      ;;
    *)
      printf '%sВерсія:%s %-12s %sПлатформа:%s %-8s %sКористувач:%s %s\n' "$c_dim" "$c_reset" "$VERSION" "$c_dim" "$c_reset" "$PLATFORM" "$c_dim" "$c_reset" "${USER:-unknown}"
      printf '%sЗвіт:%s %s\n' "$c_dim" "$c_reset" "$REPORT"
      printf '%sУвага:%s збіги — сигнали для ручної перевірки, не автоматичний доказ.\n' "$c_yellow" "$c_reset"
      printf '%sМежа захисту:%s локальний скрипт не може гарантувати захист від обходу; для цього потрібна серверна верифікація.\n' "$c_yellow" "$c_reset"
      ;;
  esac
  printf '%s%s%s\n' "$c_cyan" '────────────────────────────────────────────────────────────────' "$c_reset"
}

# ---------- compatibility diagnostics ----------

compatibility_check() {
  printf '%sПеревірка сумісності середовища%s\n' "$c_cyan" "$c_reset"
  log_section "COMPATIBILITY"

  printf 'OS: %s (%s)\n' "$OS" "$PLATFORM" | outlog
  printf 'Shell: %s\n' "${SHELL:-unknown}" | outlog

  missing_core=""
  for cmd in uname date id find grep sed awk sort head tail basename tr cat ps ls mkdir mktemp readlink file sha256sum; do
    if have "$cmd"; then
      printf '[OK]   %s\n' "$cmd" | outlog
    else
      printf '[MISS] %s\n' "$cmd" | outlog
      missing_core="$missing_core $cmd"
    fi
  done

  printf '\nОпціональні можливості:\n' | outlog
  for cmd in gzip zgrep lsof sqlite3 gcore gdb strings unzip zipinfo jar shasum diff ss netstat ip ifconfig \
             journalctl systemctl systemd-detect-virt loginctl crontab \
             lscpu lspci lsblk lsusb loginctl getent \
             apt dnf yum pacman apk zypper \
             sw_vers system_profiler ioreg launchctl osascript vmmap; do
    if have "$cmd"; then
      printf '[OK]   %s\n' "$cmd" | outlog
    else
      printf '[----] %s\n' "$cmd" | outlog
    fi
  done

  if [ "$PLATFORM" = "linux" ]; then
    printf '\nLinux distribution:\n' | outlog
    if [ -r /etc/os-release ]; then
      distro_name=$(sed -n 's/^NAME="\{0,1\}\([^"].*\)"\{0,1\}$/\1/p' /etc/os-release | safe_head 1)
      distro_version=$(sed -n 's/^VERSION_ID="\{0,1\}\([^"].*\)"\{0,1\}$/\1/p' /etc/os-release | safe_head 1)
      distro_id=$(sed -n 's/^ID="\{0,1\}\([^"].*\)"\{0,1\}$/\1/p' /etc/os-release | safe_head 1)
      printf '  %s %s (%s)\n' "${distro_name:-unknown}" "${distro_version:-unknown}" "${distro_id:-unknown}" | outlog
    else
      printf '  /etc/os-release unavailable\n' | outlog
    fi
    printf '  Desktop: %s | Session: %s | Wayland: %s\n' \
      "${XDG_CURRENT_DESKTOP:-unknown}" "${XDG_SESSION_TYPE:-unknown}" "${WAYLAND_DISPLAY:-no}" | outlog
  fi

  if [ -n "$missing_core" ]; then
    printf '\nПопередження: відсутні базові утиліти:%s\n' "$missing_core" | outlog
    printf 'Скрипт запустився, але окремі пункти можуть бути недоступні.\n' | outlog
  else
    printf '\nБазове POSIX-середовище придатне для роботи.\n' | outlog
  fi
}

# ---------- system ----------

system_info() {
  printf '%sСистемна інформація%s\n' "$c_cyan" "$c_reset"
  log_section "SYSTEM INFO"

  {
    echo "Date: $(date 2>/dev/null)"
    echo "User: $(id -un 2>/dev/null)"
    if have hostname; then
      echo "Host: $(hostname 2>/dev/null)"
    else
      echo "Host: $(uname -n 2>/dev/null)"
    fi
    echo "Kernel: $(uname -a 2>/dev/null)"

    if [ "$PLATFORM" = "linux" ]; then
      if [ -r /etc/os-release ]; then
        cat /etc/os-release
      else
        for f in /etc/*release; do
          [ -r "$f" ] && cat "$f"
        done
      fi

      echo "--- CPU ---"
      if have lscpu; then
        lscpu 2>/dev/null | grep -E 'Model name|Vendor ID|Architecture'
      elif [ -r /proc/cpuinfo ]; then
        grep -E 'model name|Hardware|Processor|vendor_id' /proc/cpuinfo 2>/dev/null | safe_head 12
      else
        say_skip "CPU details unavailable"
      fi

      echo "--- GPU ---"
      if have lspci; then
        lspci 2>/dev/null | grep -Ei 'VGA|3D|Display'
      else
        say_skip "lspci unavailable"
      fi

      echo "--- Disks ---"
      if have lsblk; then
        lsblk 2>/dev/null
      elif have df; then
        df -k 2>/dev/null
      else
        say_skip "lsblk/df unavailable"
      fi

      echo "--- Network interfaces ---"
      if have ip; then
        ip -brief link 2>/dev/null || ip link 2>/dev/null
      elif have ifconfig; then
        ifconfig -a 2>/dev/null
      else
        say_skip "ip/ifconfig unavailable"
      fi

      echo "--- Virtualization ---"
      if have systemd-detect-virt; then
        systemd-detect-virt 2>/dev/null || echo none
      elif [ -r /proc/1/cgroup ]; then
        grep -Ei 'docker|podman|lxc|container|kubepods' /proc/1/cgroup 2>/dev/null | safe_head 10
      else
        say_skip "virtualization detector unavailable"
      fi

    elif [ "$PLATFORM" = "macos" ]; then
      if have sw_vers; then
        sw_vers 2>/dev/null
      fi

      echo "--- Hardware ---"
      if have system_profiler; then
        system_profiler SPHardwareDataType 2>/dev/null | safe_head 100
      else
        say_skip "system_profiler unavailable"
      fi

      echo "--- GPU ---"
      if have system_profiler; then
        system_profiler SPDisplaysDataType 2>/dev/null | safe_head 150
      else
        say_skip "system_profiler unavailable"
      fi

      echo "--- Disks ---"
      if have df; then
        df -k 2>/dev/null
      fi

      echo "--- Network interfaces ---"
      if have ifconfig; then
        ifconfig -a 2>/dev/null
      else
        say_skip "ifconfig unavailable"
      fi
    fi
  } | outlog
}

# ---------- scan roots / file scanning ----------

emit_quick_scan_roots() {
  # Fast/default scan: locations where Minecraft clients, mods, downloads and
  # temporary payloads realistically live.  The whole HOME scan is separate.
  {
    emit_minecraft_roots
    for d in "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents"; do
      [ -d "$d" ] && printf '%s\n' "$d"
    done
  } | sort -u
}

scan_temp_archives_shallow() {
  # Fast temp check: only direct files in common temp dirs. Recursive /tmp scan
  # belongs to the explicit deep mode; scanning all /tmp can include other
  # users, old test data and huge application trees.
  for d in "${TMPDIR:-/tmp}" /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] || continue
    for f in "$d"/* "$d"/.*; do
      [ -f "$f" ] || continue
      case "$f" in "$TMPBASE"/veritas_ac_*|*/veritas_ac_reports/*) continue ;; esac
      case "$(basename "$f" | tr '[:upper:]' '[:lower:]')" in
        *.jar|*.zip|*.tar.gz|*.rar|*.7z|*.so|*.dll|*.dylib) check_banned_candidate "$f" ;;
      esac
    done
  done
}

scan_temp_configs_shallow() {
  for d in "${TMPDIR:-/tmp}" /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] || continue
    for f in "$d"/* "$d"/.*; do
      [ -f "$f" ] || continue
      case "$f" in "$TMPBASE"/veritas_ac_*|*/veritas_ac_reports/*) continue ;; esac
      base=$(basename "$f" | tr '[:upper:]' '[:lower:]')
      case "$base" in
        *.json|*.toml|*.cfg|*.ini|*.txt|*.log|*.properties|*.yml|*.yaml) scan_config_file "$f" ;;
      esac
    done
  done
}

is_launcher_dir_name() {
  name=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$name" in
    *minecraft*|*launcher*|*multimc*|*polymc*|*prismlauncher*|*modrinth*|\
    *curseforge*|*technic*|*atlauncher*|*gdlauncher*|*feedthebeast*|\
    feather|featherclient|feather-client) return 0 ;;
  esac
  return 1
}

# Discover renamed/forked launchers from their user-data directory names.  This
# only examines immediate children of conventional app-data locations.
emit_launcher_children() {
  parent=$1
  [ -d "$parent" ] || return 0
  for d in "$parent"/* "$parent"/.*; do
    [ -d "$d" ] || continue
    base=$(basename "$d")
    is_launcher_dir_name "$base" && printf '%s\n' "$d"
  done
}

emit_minecraft_roots() {
  {
    if [ "$PLATFORM" = "linux" ]; then
      for d in \
        "$HOME/.minecraft" "$HOME/.local/share/PrismLauncher" \
        "$HOME/.local/share/PolyMC" "$HOME/.local/share/multimc" \
        "$HOME/.local/share/ModrinthApp" "$HOME/.local/share/Technic" \
        "$HOME/.local/share/FTB" "$HOME/.local/share/CurseForge" \
        "$HOME/.config/ATLauncher" "$HOME/.config/GDLauncher" \
        "$HOME/.config/feather" "$HOME/.config/PrismLauncher" \
        "$HOME/.config/MultiMC" "$HOME/.config/PolyMC" \
        "$HOME/.var/app/org.prismlauncher.PrismLauncher" \
        "$HOME/.var/app/org.polymc.PolyMC" \
        "$HOME/.var/app/com.modrinth.ModrinthApp" \
        "$HOME/.var/app/com.atlauncher.ATLauncher"
      do
        [ -d "$d" ] && printf '%s\n' "$d"
      done
      for parent in "$HOME/.local/share" "$HOME/.config" "$HOME/.var/app" "$HOME/snap"; do
        emit_launcher_children "$parent"
      done
    else
      for d in \
        "$HOME/Library/Application Support/minecraft" \
        "$HOME/Library/Application Support/PrismLauncher" \
        "$HOME/Library/Application Support/PolyMC" \
        "$HOME/Library/Application Support/MultiMC" \
        "$HOME/Library/Application Support/ModrinthApp" \
        "$HOME/Library/Application Support/ATLauncher" \
        "$HOME/Library/Application Support/GDLauncher" \
        "$HOME/Library/Application Support/Feather" \
        "$HOME/Library/Application Support/CurseForge" \
        "$HOME/Library/Application Support/Technic" \
        "$HOME/Library/Application Support/FTB"
      do
        [ -d "$d" ] && printf '%s\n' "$d"
      done
      emit_launcher_children "$HOME/Library/Application Support"
      emit_launcher_children "$HOME/Library/Containers"
    fi
  } | sort -u
}

find_candidate_archives() {
  root=$1
  [ -d "$root" ] || return 0

  # Filter by extension inside find itself.  This avoids spawning basename/tr
  # for every browser cache, Steam file, source tree, etc.
  find "$root" -type f \( \
    -name '*.jar' -o -name '*.JAR' -o \
    -name '*.zip' -o -name '*.ZIP' -o \
    -name '*.tar.gz' -o -name '*.TAR.GZ' -o \
    -name '*.rar' -o -name '*.RAR' -o \
    -name '*.7z' -o -name '*.7Z' -o \
    -name '*.so' -o -name '*.SO' -o \
    -name '*.dll' -o -name '*.DLL' -o \
    -name '*.dylib' -o -name '*.DYLIB' \
  \) -print 2>/dev/null
}

check_banned_candidate() {
  f=$1
  base=$(basename "$f" 2>/dev/null | tr '[:upper:]' '[:lower:]')
  norm=$(printf '%s' "$base" | tr -cd 'a-z0-9')
  if printf '%s\n' "$norm" | grep -Eq "($BANNED_NORMALIZED)" 2>/dev/null; then
    size=$(file_size_bytes "$f")
    modified='unknown'
    if have stat; then
      modified=$(stat -c '%y' "$f" 2>/dev/null)
      [ -n "$modified" ] || modified=$(stat -f '%Sm' "$f" 2>/dev/null)
    fi
    hash='unavailable'
    if have sha256sum; then
      hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    elif have shasum; then
      hash=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')
    fi
    printf '[NAME] %s | bytes=%s | modified=%s | sha256=%s\n' "$f" "$size" "$modified" "${hash:-unavailable}"
  fi
}

scan_banned_root() {
  root=$1
  [ -d "$root" ] || return 0
  find_candidate_archives "$root" |
  while IFS= read -r f; do
    check_banned_candidate "$f"
  done
}

search_banned_files() {
  printf '%sПошук підозрілих JAR/архівів/бібліотек...%s\n' "$c_cyan" "$c_reset"
  printf 'Швидкий режим: Minecraft/launcher/Downloads/Desktop/Documents/temp.\n'
  log_section "BANNED FILE NAMES"

  tmpdir=$(make_private_tmpdir) || return 1
  tmp="$tmpdir/files.txt"
  : > "$tmp" 2>/dev/null || { rmdir "$tmpdir" 2>/dev/null; return 1; }

  emit_quick_scan_roots |
  while IFS= read -r root; do
    printf '  -> %s\n' "$root"
    scan_banned_root "$root" >> "$tmp"
  done

  printf '  -> temp (shallow)\n'
  scan_temp_archives_shallow >> "$tmp"

  # Also check files stored directly in HOME without recursively walking HOME.
  for f in "$HOME"/* "$HOME"/.*; do
    [ -f "$f" ] || continue
    case "$f" in "$REPORT"|"$REPORT_DIR"/*) continue ;; esac
    case "$(basename "$f" | tr '[:upper:]' '[:lower:]')" in
      *.jar|*.zip|*.tar.gz|*.rar|*.7z|*.so|*.dll|*.dylib) check_banned_candidate "$f" >> "$tmp" ;;
    esac
  done

  if [ -s "$tmp" ]; then
    sort -u "$tmp" 2>/dev/null | outlog
    count=$(sort -u "$tmp" 2>/dev/null | wc -l | tr -d ' ')
    printf 'Знайдено збігів: %s\n' "${count:-0}" | outlog
  else
    printf 'Збігів за назвами не знайдено.\n' | outlog
  fi
  rm -f "$tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
  printf 'Пункт 3 завершено.\n'
}

find_candidate_configs() {
  root=$1
  [ -d "$root" ] || return 0

  # Dependency/vendor/cache trees create enormous noise and are not runtime
  # Minecraft config locations. -prune is supported by GNU, BSD/macOS and BusyBox find.
  find "$root" \
    \( -type d \( \
      -name node_modules -o -name .git -o -name .gradle -o \
      -name .cache -o -name __pycache__ -o -name target -o \
      -name dist -o -name build \
    \) -prune \) -o \
    \( -type f -mtime -14 \( \
      -name '*.json' -o -name '*.JSON' -o \
      -name '*.toml' -o -name '*.TOML' -o \
      -name '*.cfg' -o -name '*.CFG' -o \
      -name '*.ini' -o -name '*.INI' -o \
      -name '*.txt' -o -name '*.TXT' -o \
      -name '*.log' -o -name '*.LOG' -o \
      -name '*.properties' -o -name '*.PROPERTIES' -o \
      -name '*.yml' -o -name '*.YML' -o \
      -name '*.yaml' -o -name '*.YAML' \
    \) -print \) 2>/dev/null
}
file_size_bytes() {
  f=$1
  if have stat; then
    n=$(stat -c '%s' "$f" 2>/dev/null)
    case "$n" in ''|*[!0-9]*) n=$(stat -f '%z' "$f" 2>/dev/null) ;; esac
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    printf '%s\n' "$n"
  else
    printf '0\n'
  fi
}

scan_config_file() {
  f=$1
  case "$f" in
    "$REPORT"|"$REPORT_DIR"/*|*/veritas_ac_reports/*|"$TMPBASE"/veritas_ac_*) return 0 ;;
    */node_modules/*|*/.git/*|*/.gradle/*|*/.cache/*|*/__pycache__/*|*/target/*|*/dist/*|*/build/*) return 0 ;;
  esac

  # A multi-gigabyte log/config can freeze grep.
  size=$(file_size_bytes "$f")
  if [ "$size" -gt 33554432 ] 2>/dev/null; then
    printf '[SKIP >32MiB] %s\n' "$f"
    return 0
  fi

  # Manuals/checker source files contain the entire blacklist by design.
  if is_reference_list_file "$f"; then
    return 0
  fi

  strong_re=$(content_re "$CONTENT_STRONG_PATTERN")
  weak_re=$(content_re "$CONTENT_WEAK_PATTERN")

  # Filename: whole-token matching only; no "ares" inside "compares".
  base=$(basename "$f" 2>/dev/null)
  name_hit=0
  if printf '%s\n' "$base" | grep -Eiq "$strong_re" 2>/dev/null; then
    name_hit=1
  elif is_minecraft_related_path "$f" && printf '%s\n' "$base" | grep -Eiq "$weak_re" 2>/dev/null; then
    name_hit=1
  fi
  [ "$name_hit" -eq 1 ] && printf '[NAME] %s\n' "$f"

  [ -r "$f" ] || return 0

  # Strong terms are searched everywhere in quick roots.
  if grep -qiE "$strong_re" "$f" 2>/dev/null; then
    printf '[CONTENT] %s\n' "$f"
    grep -inE "$strong_re" "$f" 2>/dev/null | safe_head 5 | sed 's/^/    /'
    return 0
  fi

  # Ambiguous/common terms only count inside actual Minecraft/launcher trees.
  if is_minecraft_related_path "$f" && grep -qiE "$weak_re" "$f" 2>/dev/null; then
    printf '[CONTENT-WEAK/MC] %s\n' "$f"
    grep -inE "$weak_re" "$f" 2>/dev/null | safe_head 5 | sed 's/^/    /'
  fi
}
scan_config_root() {
  root=$1
  [ -d "$root" ] || return 0
  find_candidate_configs "$root" |
  while IFS= read -r f; do
    scan_config_file "$f"
  done
}

search_configs() {
  printf '%sПошук конфігів і текстових слідів за 14 днів...%s\n' "$c_cyan" "$c_reset"
  printf 'Швидкий режим: точні токени, без node_modules/.git/build/cache.\n'
  printf 'Загальні назви (delta/future/meteor тощо) враховуються лише у Minecraft-шляхах.\n'
  log_section "CONFIG/TEXT HITS (14 DAYS)"

  tmpdir=$(make_private_tmpdir) || return 1
  tmp="$tmpdir/configs.txt"
  : > "$tmp" 2>/dev/null || { rmdir "$tmpdir" 2>/dev/null; return 1; }

  emit_quick_scan_roots |
  while IFS= read -r root; do
    printf '  -> %s\n' "$root"
    scan_config_root "$root" >> "$tmp"
  done
  printf '  -> temp (shallow)\n'
  scan_temp_configs_shallow >> "$tmp"

  if [ -s "$tmp" ]; then
    cat "$tmp" | outlog
  else
    printf 'Збігів у конфігах/текстових файлах не знайдено.\n' | outlog
  fi
  rm -f "$tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
  printf 'Пункт 4 завершено.\n'
}

# ---------- Minecraft locations ----------

minecraft_locations() {
  printf '%sMinecraft / launcher locations%s\n' "$c_cyan" "$c_reset"
  log_section "MINECRAFT LOCATIONS"

  tmpdir=$(make_private_tmpdir) || return 1
  roots_tmp="$tmpdir/minecraft_roots.txt"
  emit_minecraft_roots > "$roots_tmp"

  if [ -s "$roots_tmp" ]; then
    cat "$roots_tmp" | outlog
  else
    printf 'Відомих Minecraft/launcher каталогів не знайдено.\n' | outlog
  fi

  printf '\nmods/config/versions у відомих launcher-каталогах:\n' | outlog
  while IFS= read -r root; do
    find "$root" -type d \( -name mods -o -name config -o -name versions \) -print 2>/dev/null
  done < "$roots_tmp" | safe_head 500 | outlog

  rm -f "$roots_tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
  printf 'Пункт 5 завершено.\n'
}

list_jars_directly_in_dir() {
  d=$1
  [ -d "$d" ] || return 0
  for f in "$d"/*.jar "$d"/*.JAR; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}

file_sha256() {
  f=$1
  if have sha256sum; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$f" 2>/dev/null | awk '{print $1}'
  else
    printf 'unavailable\n'
  fi
}

# JAR files are ZIP archives.  Listing their entries, rather than extracting
# them, is read-only and avoids executing any code contained in a mod.
archive_entries() {
  f=$1
  if have unzip; then
    unzip -Z1 "$f" 2>/dev/null
  elif have zipinfo; then
    zipinfo -1 "$f" 2>/dev/null
  elif have jar; then
    jar tf "$f" 2>/dev/null
  else
    return 127
  fi
}

mod_archive_paths() {
  emit_minecraft_roots |
  while IFS= read -r root; do
    find "$root" -type d -name mods -print 2>/dev/null | safe_head 500 |
    while IFS= read -r d; do
      list_jars_directly_in_dir "$d"
    done
  done
}

mod_archive_inventory() {
  mod_archive_paths | sort -u |
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    printf '%s|%s|%s\n' "$(file_sha256 "$f")" "$(file_size_bytes "$f")" "$f"
  done | sort
}

scan_mod_archive_file() {
  f=$1
  size=$(file_size_bytes "$f")
  if [ "$size" -gt 134217728 ] 2>/dev/null; then
    printf '[SKIP >128MiB] %s\n' "$f"
    return 0
  fi

  hash=$(file_sha256 "$f")
  entry_hits=$(archive_entries "$f" | grep -iE "$ARCHIVE_SIGNATURE_PATTERN" 2>/dev/null | safe_head 5)
  if [ -n "$entry_hits" ]; then
    printf '[ARCHIVE-ENTRY] %s | sha256=%s\n' "$f" "$hash"
    printf '%s\n' "$entry_hits" | sed 's/^/    /'
  fi

  # Obfuscated mods may not retain descriptive entry names.  ASCII strings are
  # an additional, lower-confidence signal; the JAR is never extracted or run.
  if have strings; then
    string_hits=$(strings "$f" 2>/dev/null | grep -iE "$ARCHIVE_SIGNATURE_PATTERN" 2>/dev/null | safe_head 5)
    if [ -n "$string_hits" ]; then
      printf '[ARCHIVE-STRINGS] %s | sha256=%s\n' "$f" "$hash"
      printf '%s\n' "$string_hits" | sed 's/^/    /'
    fi
  fi
}

scan_active_archive_contents() {
  printf '%sАналіз вмісту активних Minecraft JAR%s\n' "$c_cyan" "$c_reset"
  printf 'Перевіряються записи ZIP/JAR і рядки без розпакування чи запуску модів.\n'
  log_section "ACTIVE MOD ARCHIVE CONTENTS"

  if ! have unzip && ! have zipinfo && ! have jar; then
    echo "Немає unzip/zipinfo/jar; аналіз структури JAR недоступний." | outlog
    return 1
  fi

  tmpdir=$(make_private_tmpdir) || return 1
  tmp="$tmpdir/archive_hits.txt"
  : > "$tmp" 2>/dev/null || { rmdir "$tmpdir" 2>/dev/null; return 1; }

  mod_archive_paths | sort -u |
  while IFS= read -r f; do
    scan_mod_archive_file "$f"
  done > "$tmp"

  if [ -s "$tmp" ]; then
    cat "$tmp" | outlog
  else
    printf 'Підозрілих сильних сигнатур усередині активних JAR не знайдено.\n' | outlog
  fi
  rm -f "$tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
  printf 'Аналіз активних JAR завершено.\n'
}

create_mod_baseline() {
  printf '%sСтворення baseline інвентарю активних модів%s\n' "$c_cyan" "$c_reset"
  printf 'Створюй baseline лише на відомо чистій збірці; файл: %s\n' "$MOD_BASELINE"
  log_section "CREATE MOD BASELINE"

  tmpdir=$(make_private_tmpdir) || return 1
  tmp="$tmpdir/mod_baseline.txt"
  mod_archive_inventory > "$tmp"
  if [ -s "$tmp" ]; then
    mv "$tmp" "$MOD_BASELINE" 2>/dev/null || {
      echo "Не вдалося зберегти baseline: $MOD_BASELINE" | outlog
      rm -f "$tmp" 2>/dev/null
      rmdir "$tmpdir" 2>/dev/null
      return 1
    }
    count=$(wc -l < "$MOD_BASELINE" 2>/dev/null | tr -d ' ')
    printf '[OK] Baseline збережено: %s JAR | %s\n' "${count:-0}" "$MOD_BASELINE" | outlog
  else
    echo "Активні JAR у mods-папках не знайдені; baseline не створено." | outlog
    rm -f "$tmp" 2>/dev/null
  fi
  rmdir "$tmpdir" 2>/dev/null
}

compare_mod_baseline() {
  printf '%sПорівняння активних модів із baseline%s\n' "$c_cyan" "$c_reset"
  log_section "COMPARE MOD BASELINE"

  if [ ! -r "$MOD_BASELINE" ]; then
    printf '[MISS] Baseline не знайдено: %s\n' "$MOD_BASELINE" | outlog
    return 1
  fi
  if ! have diff; then
    echo "diff недоступний; порівняння baseline пропущено." | outlog
    return 1
  fi

  tmpdir=$(make_private_tmpdir) || return 1
  tmp="$tmpdir/current_mods.txt"
  mod_archive_inventory > "$tmp"
  if diff -q "$MOD_BASELINE" "$tmp" >/dev/null 2>&1; then
    printf '[OK] Active mods збігаються з baseline.\n' | outlog
  else
    printf '[BASELINE-DIFF] - рядок є лише в baseline; + рядок є лише зараз.\n' | outlog
    diff -u "$MOD_BASELINE" "$tmp" 2>/dev/null | safe_head 400 | outlog
  fi
  rm -f "$tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
}

active_mods() {
  printf '%sАктивні/встановлені mods-папки%s\n' "$c_cyan" "$c_reset"
  log_section "ACTIVE MODS"

  tmpdir=$(make_private_tmpdir) || return 1
  roots_tmp="$tmpdir/minecraft_roots.txt"
  emit_minecraft_roots > "$roots_tmp"

  while IFS= read -r root; do
    find "$root" -type d -name mods -print 2>/dev/null
  done < "$roots_tmp" | safe_head 500 |
  while IFS= read -r d; do
    echo "===== $d ====="
    list_jars_directly_in_dir "$d"
  done | outlog

  rm -f "$roots_tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
  printf 'Пункт 6 завершено.\n'
}

# ---------- explicit deep scan ----------

deep_scan_home() {
  printf '%sГлибокий scan усього HOME%s\n' "$c_yellow" "$c_reset"
  printf 'Цей режим НАВМИСНО може працювати довго на великих HOME.\n'
  printf 'На екрані буде видно поточну фазу, тому це не виглядатиме як зависання.\n'
  log_section "DEEP HOME SCAN"

  tmpdir=$(make_private_tmpdir) || return 1
  tmp="$tmpdir/deep.txt"
  : > "$tmp" 2>/dev/null || { rmdir "$tmpdir" 2>/dev/null; return 1; }

  printf '[1/2] Архіви/JAR/бібліотеки у %s ...\n' "$HOME"
  scan_banned_root "$HOME" >> "$tmp"
  printf '[2/2] Конфіги/логи за 14 днів у %s ...\n' "$HOME"
  scan_config_root "$HOME" >> "$tmp"

  if [ -s "$tmp" ]; then
    cat "$tmp" | outlog
  else
    printf 'Збігів у глибокому скануванні не знайдено.\n' | outlog
  fi
  rm -f "$tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
  printf 'Глибоке сканування завершено.\n'
}

# ---------- Minecraft logs / accounts ----------

scan_user_logs_dir() {
  d=$1
  [ -d "$d" ] || return 0

  find "$d" -type f \( -name '*.log' -o -name '*.log.gz' \) -print 2>/dev/null |
  while IFS= read -r f; do
    case "$f" in
      *.gz)
        if have zgrep; then
          zgrep -i 'setting user:' "$f" 2>/dev/null
        elif have gzip; then
          gzip -cd "$f" 2>/dev/null | grep -i 'setting user:' 2>/dev/null
        fi
        ;;
      *)
        grep -i 'setting user:' "$f" 2>/dev/null
        ;;
    esac
  done
}

twinks_from_logs() {
  printf '%sПошук імен користувачів у Minecraft-логах%s\n' "$c_cyan" "$c_reset"
  log_section "MINECRAFT USERS FROM LOGS"

  tmpdir=$(make_private_tmpdir) || return 1
  tmp="$tmpdir/users.txt"
  : > "$tmp" 2>/dev/null || { rmdir "$tmpdir" 2>/dev/null; return 1; }

  emit_minecraft_roots |
  while IFS= read -r root; do
    scan_user_logs_dir "$root"
  done | awk '{print $NF}' | sort -u > "$tmp"

  cat "$tmp" | outlog
  rm -f "$tmp" 2>/dev/null
  rmdir "$tmpdir" 2>/dev/null
}

# ---------- recent / downloads / trash ----------

recent_activity() {
  printf '%sRecent / Trash / Downloads%s\n' "$c_cyan" "$c_reset"
  log_section "RECENT / TRASH / DOWNLOADS"

  {
    if [ "$PLATFORM" = "linux" ]; then
      echo "--- GNOME recent ---"
      if [ -f "$HOME/.local/share/recently-used.xbel" ]; then
        grep -iE 'href|bookmark' "$HOME/.local/share/recently-used.xbel" 2>/dev/null | safe_tail 100
      else
        say_skip "GNOME recently-used.xbel not found"
      fi

      echo "--- KDE recent ---"
      for d in \
        "$HOME/.local/share/RecentDocuments" \
        "$HOME/.local/share/kactivitymanagerd"
      do
        [ -d "$d" ] || continue
        find "$d" -type f -print 2>/dev/null | safe_head 100
      done
      for f in \
        "$HOME/.config/kdeglobals" \
        "$HOME/.config/kactivitymanagerdrc"
      do
        [ -f "$f" ] && printf '%s\n' "$f"
      done

      echo "--- Trash ---"
      ls -la "$HOME/.local/share/Trash/files" "$HOME/.local/share/Trash/info" 2>/dev/null

      echo "--- Downloads 14d ---"
      if [ -d "$HOME/Downloads" ]; then
        find "$HOME/Downloads" -type f -mtime -14 -print 2>/dev/null | safe_tail 300
      fi

    else
      echo "--- Trash ---"
      ls -la "$HOME/.Trash" 2>/dev/null

      echo "--- Downloads 14d ---"
      if [ -d "$HOME/Downloads" ]; then
        find "$HOME/Downloads" -type f -mtime -14 -print 2>/dev/null | safe_tail 300
      fi

      echo "--- Gatekeeper quarantine DB ---"
      qdb="$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
      if [ -f "$qdb" ] && have sqlite3; then
        sqlite3 "$qdb" \
          'SELECT LSQuarantineTimeStamp,LSQuarantineAgentName,LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 100;' \
          2>/dev/null
      else
        say_skip "sqlite3 or quarantine DB unavailable"
      fi
    fi
  } | outlog
  printf 'Пункт 8 завершено.\n'
}

# ---------- browser DB locations ----------

is_browser_dir_name() {
  name=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$name" in
    *browser*|*chrome*|*chromium*|*firefox*|*mozilla*|*brave*|*vivaldi*|\
    *opera*|*yandex*|*waterfox*|*librewolf*|*floorp*|*qutebrowser*|\
    *falkon*|*epiphany*|*midori*|tor|torbrowser|tor-browser|org.torproject*|\
    zen|zen-browser|app.zen*) return 0 ;;
  esac
  return 1
}

emit_browser_children() {
  parent=$1
  [ -d "$parent" ] || return 0
  for d in "$parent"/* "$parent"/.*; do
    [ -d "$d" ] || continue
    base=$(basename "$d")
    is_browser_dir_name "$base" && printf '%s\n' "$d"
  done
}

emit_browser_data_roots_linux() {
  {
    for d in "$HOME/.mozilla" "$HOME/.tor" "$HOME/.waterfox" "$HOME/.librewolf"; do
      [ -d "$d" ] && printf '%s\n' "$d"
    done
    for parent in "$HOME/.config" "$HOME/.local/share" "$HOME/.var/app" "$HOME/snap"; do
      emit_browser_children "$parent"
    done
  } | sort -u
}

emit_browser_data_roots_macos() {
  {
    [ -d "$HOME/Library/Safari" ] && printf '%s\n' "$HOME/Library/Safari"
    for parent in "$HOME/Library/Application Support" "$HOME/Library/Containers" "$HOME/Library/Group Containers"; do
      emit_browser_children "$parent"
    done
  } | sort -u
}

# Browser engines use a small set of history database names even when the
# product is a fork or has been renamed.  Only metadata paths are listed.
find_browser_history_files() {
  for d in "$@"; do
    [ -d "$d" ] || continue
    find "$d" \
      \( -type d \( -name Cache -o -name 'Code Cache' -o -name GPUCache -o -name 'Service Worker' \) -prune \) -o \
      \( -type f \( \
        -name History -o -name 'History.db' -o -name places.sqlite -o \
        -name history.sqlite -o -name history.db -o -name BrowserHistory.db \
      \) -print \) 2>/dev/null
  done
}

browser_desktop_entries_linux() {
  for d in "$HOME/.local/share/applications" /usr/local/share/applications /usr/share/applications; do
    [ -d "$d" ] || continue
    find "$d" -type f -name '*.desktop' -exec \
      grep -lE '^Categories=.*WebBrowser' {} \; 2>/dev/null
  done
}

browser_apps_macos() {
  for app in /Applications/*.app "$HOME/Applications"/*.app; do
    [ -d "$app" ] || continue
    base=$(basename "$app" | tr '[:upper:]' '[:lower:]')
    case "$base" in
      *browser*.app|*chrome*.app|*chromium*.app|*firefox*.app|*safari*.app|\
      *opera*.app|*vivaldi*.app|*brave*.app|*edge*.app|*tor*.app|*zen*.app|\
      *waterfox*.app|*librewolf*.app|*floorp*.app) printf '%s\n' "$app" ;;
    esac
  done
}

browser_history_locations() {
  printf '%sПошук баз історії браузерів і встановлених браузерів%s\n' "$c_cyan" "$c_reset"
  log_section "BROWSER HISTORY DATABASES"

  {
    if [ "$PLATFORM" = "linux" ]; then
      echo "--- Browser desktop entries (Linux) ---"
      browser_desktop_entries_linux | sort -u | safe_head 300
      echo "--- Discovered history databases (profiles, Flatpak, Snap, forks) ---"
      emit_browser_data_roots_linux |
      while IFS= read -r root; do
        find_browser_history_files "$root"
      done | sort -u | safe_head 500

    else
      echo "--- Browser applications (macOS) ---"
      browser_apps_macos | sort -u | safe_head 300
      echo "--- Discovered history databases (Safari, profiles, containers, forks) ---"
      emit_browser_data_roots_macos |
      while IFS= read -r root; do
        find_browser_history_files "$root"
      done | sort -u | safe_head 500
    fi
  } | outlog

  printf '\nПримітка: БД лише знаходяться; програма їх не змінює.\n'
  printf 'Пункт 9 завершено.\n'
}

# ---------- processes / libraries / network ----------

java_processes() {
  printf '%sJava / Minecraft processes%s\n' "$c_cyan" "$c_reset"
  log_section "JAVA / MINECRAFT PROCESSES"

  # ps -ef is more portable than platform-specific pgrep flags.
  ps -ef 2>/dev/null | grep -Ei '[j]ava|[m]inecraft' | outlog

  printf '\nВведи PID для перегляду відкритих JAR/бібліотек (або Enter щоб пропустити): '
  IFS= read -r pid
  [ -n "$pid" ] || return 0

  case "$pid" in
    *[!0-9]*)
      echo "Невірний PID"
      return 1
      ;;
  esac

  log_section "PROCESS $pid LIBRARIES / FILES / NETWORK"

  {
    if [ "$PLATFORM" = "linux" ]; then
      if [ -r "/proc/$pid/maps" ]; then
        awk '{print $6}' "/proc/$pid/maps" 2>/dev/null |
          grep -E '\.so($|\.)|\.jar$|/tmp/|/var/tmp/|/dev/shm/' |
          sort -u
      else
        say_skip "/proc/$pid/maps unavailable"
      fi

      if have lsof; then
        echo "--- lsof ---"
        lsof -p "$pid" 2>/dev/null |
          grep -Ei '\.so|\.jar|/tmp/|/var/tmp/|/dev/shm/'
      fi

      echo "--- network ---"
      if have ss; then
        ss -tupn 2>/dev/null | grep -F "pid=$pid,"
      elif have lsof; then
        lsof -Pan -p "$pid" -i 2>/dev/null
      elif have netstat; then
        echo "PID mapping unavailable; showing general network table:"
        netstat -an 2>/dev/null | safe_head 250
      else
        say_skip "ss/lsof/netstat unavailable"
      fi

    else
      if have lsof; then
        echo "--- lsof ---"
        lsof -p "$pid" 2>/dev/null | grep -Ei '\.jar|\.dylib|\.so|/tmp/'
      else
        say_skip "lsof unavailable"
      fi

      if have vmmap; then
        echo "--- vmmap ---"
        vmmap "$pid" 2>/dev/null | grep -Ei '\.dylib|\.so|/private/tmp|/tmp'
      else
        say_skip "vmmap unavailable"
      fi

      echo "--- network ---"
      if have lsof; then
        lsof -Pan -p "$pid" -i 2>/dev/null
      elif have netstat; then
        echo "PID mapping unavailable; showing general network table:"
        netstat -an 2>/dev/null | safe_head 250
      else
        say_skip "lsof/netstat unavailable"
      fi
    fi
  } | outlog
}

# ---------- optional memory scan ----------

memory_scan() {
  printf '%sОпціональний пошук рядків у дампі памʼяті Minecraft/Java%s\n' "$c_cyan" "$c_reset"
  printf 'Потрібні права на debug/ptrace. Дамп видаляється після перевірки.\n'
  printf 'PID: '
  IFS= read -r pid

  case "$pid" in
    ''|*[!0-9]*)
      echo "Невірний PID"
      return 1
      ;;
  esac

  log_section "MEMORY STRING SCAN PID $pid"

  if [ "$PLATFORM" != "linux" ]; then
    echo "На macOS автоматичний дамп вимкнено; використай lsof/vmmap." | outlog
    return 0
  fi

  if ! have strings; then
    echo "strings не знайдено; memory scan недоступний." | outlog
    return 1
  fi

  dump_dir=$(make_private_tmpdir) || {
    echo "Не вдалося створити захищений тимчасовий каталог; memory scan пропущено." | outlog
    return 1
  }
  prefix="$dump_dir/dump"
  dump_file=""

  if have gcore; then
    gcore -o "$prefix" "$pid" >/dev/null 2>&1
    for f in "${prefix}".* "$prefix"; do
      [ -f "$f" ] && {
        dump_file=$f
        break
      }
    done
  elif have gdb; then
    dump_file="${prefix}.core"
    gdb --batch \
      -ex "attach $pid" \
      -ex "gcore $dump_file" \
      -ex "detach" \
      -ex "quit" >/dev/null 2>&1
  else
    echo "Немає gcore/gdb; memory scan пропущено." | outlog
    rmdir "$dump_dir" 2>/dev/null
    return 1
  fi

  if [ -n "$dump_file" ] && [ -f "$dump_file" ]; then
    strings "$dump_file" 2>/dev/null |
      grep -iE "$BANNED_PATTERN" |
      safe_head 200 |
      outlog
    rm -f "$dump_file" "${prefix}".* "$prefix" 2>/dev/null
  else
    echo "Не вдалося створити дамп (можливі обмеження ptrace/прав)." | outlog
  fi
  rmdir "$dump_dir" 2>/dev/null
}

# ---------- shell history ----------

shell_history() {
  printf '%sShell history: релевантні команди%s\n' "$c_cyan" "$c_reset"
  log_section "SHELL HISTORY"

  {
    [ -r "$HOME/.bash_history" ] && cat "$HOME/.bash_history"
    [ -r "$HOME/.zsh_history" ] && cat "$HOME/.zsh_history"
    [ -r "$HOME/.local/share/fish/fish_history" ] && cat "$HOME/.local/share/fish/fish_history"
  } 2>/dev/null |
    grep -iE 'rm |mv |wget |curl |git |shred|truncate|history -c|unset HISTFILE' |
    safe_tail 150 |
    outlog

  printf '\nТакі команди самі по собі не є доказом порушення.\n'
}

# ---------- persistence ----------

list_files_one_level() {
  d=$1
  pattern=$2
  [ -d "$d" ] || return 0

  # Replaces non-portable "find -maxdepth 1".
  for f in "$d"/$pattern; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}

persistence() {
  printf '%sАвтозапуск / persistence%s\n' "$c_cyan" "$c_reset"
  log_section "PERSISTENCE / AUTOSTART"

  {
    if [ "$PLATFORM" = "linux" ]; then
      echo "=== USER AUTOSTART ==="
      ls -la "$HOME/.config/autostart" 2>/dev/null
      for f in "$HOME"/.config/autostart/*.desktop; do
        [ -f "$f" ] || continue
        echo "--- $f ---"
        cat "$f" 2>/dev/null
      done

      echo "=== XDG AUTOSTART ==="
      ls -la /etc/xdg/autostart 2>/dev/null

      echo "=== SYSTEMD USER ENABLED ==="
      if have systemctl; then
        systemctl --user list-unit-files --state=enabled 2>/dev/null
      else
        say_skip "systemctl unavailable (non-systemd distro is OK)"
      fi

      echo "=== SYSTEMD USER TIMERS ==="
      if have systemctl; then
        systemctl --user list-timers --all 2>/dev/null
      else
        say_skip "systemctl unavailable"
      fi

      echo "=== CRON ==="
      if have crontab; then
        crontab -l 2>/dev/null
      else
        say_skip "crontab unavailable"
      fi
      ls -la /etc/cron* /var/spool/cron* 2>/dev/null

      echo "=== SHELL RC ==="
      for f in \
        "$HOME/.bashrc" \
        "$HOME/.zshrc" \
        "$HOME/.profile" \
        "$HOME/.bash_profile" \
        "$HOME/.config/fish/config.fish"
      do
        [ -r "$f" ] || continue
        echo "--- $f ---"
        grep -inE 'wget|curl|python|bash|sh |exec|nohup|LD_PRELOAD' "$f" 2>/dev/null
      done

    else
      echo "=== launchctl ==="
      if have launchctl; then
        launchctl list 2>/dev/null
      else
        say_skip "launchctl unavailable"
      fi

      echo "=== LaunchAgents / Daemons ==="
      list_files_one_level "$HOME/Library/LaunchAgents" '*.plist'
      list_files_one_level /Library/LaunchAgents '*.plist'
      list_files_one_level /Library/LaunchDaemons '*.plist'

      echo "=== Login Items ==="
      if have osascript; then
        osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null
      else
        say_skip "osascript unavailable"
      fi
    fi
  } | outlog
}

# ---------- USB / logs ----------

usb_logs() {
  printf '%sUSB / system logs%s\n' "$c_cyan" "$c_reset"
  log_section "USB / SYSTEM LOGS"

  {
    if [ "$PLATFORM" = "linux" ]; then
      if have journalctl; then
        journalctl -k --since '14 days ago' 2>/dev/null |
          grep -iE 'usb-storage|usb |usb:|attached|disconnect' |
          safe_tail 200

        echo "--- journald lifecycle ---"
        journalctl -u systemd-journald.service --since today 2>/dev/null |
          grep -iE 'cleared|rotate|vacuum|stop|start' |
          safe_tail 100

      elif have dmesg; then
        dmesg 2>/dev/null |
          grep -iE 'usb-storage|usb |attached|disconnect' |
          safe_tail 200

      elif [ -d /sys/bus/usb/devices ]; then
        echo "No journalctl/dmesg access; current USB sysfs entries:"
        find /sys/bus/usb/devices -type f \( -name product -o -name manufacturer -o -name serial \) -print 2>/dev/null |
          safe_head 200
      else
        say_skip "journalctl/dmesg/sysfs USB info unavailable"
      fi

    else
      if have system_profiler; then
        system_profiler SPUSBDataType 2>/dev/null
      else
        say_skip "system_profiler unavailable"
      fi

      echo "--- IOUSB ---"
      if have ioreg; then
        ioreg -p IOUSB -l -w 0 2>/dev/null | safe_head 300
      else
        say_skip "ioreg unavailable"
      fi

      echo "--- 14d log ---"
      if have log; then
        log show --last 14d --style compact 2>/dev/null |
          grep -iE 'USB|IOUSB|mass storage|external disk' |
          safe_tail 200
      else
        say_skip "macOS log utility unavailable"
      fi
    fi
  } | outlog
}

# ---------- Linux-specific execution traces ----------

linux_execution_traces() {
  printf '%sLinux execution traces / loaded files%s\n' "$c_cyan" "$c_reset"
  log_section "LINUX EXECUTION TRACES"

  if [ "$PLATFORM" != "linux" ]; then
    printf 'Цей пункт доступний лише на Linux.\n' | outlog
    return 0
  fi

  {
    echo "--- Java/Minecraft command lines ---"
    ps -eo pid=,user=,lstart=,etime=,comm=,args= 2>/dev/null |
      grep -Ei '[j]ava|[j]avaw|[m]inecraft' | safe_head 200

    echo "--- Suspicious executable files in user runtime locations ---"
    for d in "$HOME/.local/bin" "$HOME/.config/autostart" "$HOME/.cache" "$HOME/.local/share" /tmp /var/tmp; do
      [ -d "$d" ] || continue
      find "$d" -type f -mtime -30 \( -perm -u+x -o -name '*.AppImage' -o -name '*.sh' -o -name '*.run' \) \
        -print 2>/dev/null | while IFS= read -r f; do
          base=$(basename "$f" | tr '[:upper:]' '[:lower:]')
          if printf '%s\n' "$base" | grep -Eq "$BANNED_PATTERN"; then
            printf '[NAME] %s\n' "$f"
          fi
        done
    done

    echo "--- Loaded kernel modules (inventory only) ---"
    if have lsmod; then
      lsmod 2>/dev/null | safe_head 200
    elif [ -r /proc/modules ]; then
      safe_head 200 < /proc/modules
    else
      say_skip "/proc/modules and lsmod unavailable"
    fi
  } | outlog
}

linux_package_history() {
  printf '%sLinux package/install history%s\n' "$c_cyan" "$c_reset"
  log_section "LINUX PACKAGE HISTORY"

  if [ "$PLATFORM" != "linux" ]; then
    printf 'Цей пункт доступний лише на Linux.\n' | outlog
    return 0
  fi

  {
    echo "--- Recent package manager logs ---"
    for f in /var/log/apt/history.log /var/log/dpkg.log /var/log/dnf.log \
             /var/log/yum.log /var/log/pacman.log /var/log/emerge.log; do
      [ -r "$f" ] || continue
      echo "### $f"
      tail -n 120 "$f" 2>/dev/null
    done
    echo "--- Installed packages matching audit terms ---"
    if have dpkg-query; then
      dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Ei "$BANNED_PATTERN" | safe_head 200
    elif have rpm; then
      rpm -qa 2>/dev/null | grep -Ei "$BANNED_PATTERN" | safe_head 200
    elif have pacman; then
      pacman -Q 2>/dev/null | grep -Ei "$BANNED_PATTERN" | safe_head 200
    else
      say_skip "dpkg-query/rpm/pacman unavailable"
    fi
  } | outlog
}

# ---------- full scan / report ----------

full_scan() {
  header
  printf '%sПовне сканування (без дампу памʼяті)%s\n' "$c_green" "$c_reset"
  compatibility_check
  system_info
  search_banned_files
  search_configs
  minecraft_locations
  active_mods
  scan_active_archive_contents
  twinks_from_logs
  recent_activity
  browser_history_locations
  shell_history
  persistence
  usb_logs
  linux_execution_traces
  linux_package_history
  printf '\n%sГотово.%s Звіт: %s\n' "$c_green" "$c_reset" "$REPORT"
}

show_report() {
  if [ ! -f "$REPORT" ]; then
    echo "Звіт ще не створено."
    return 0
  fi

  lines=$(wc -l < "$REPORT" 2>/dev/null | tr -d ' ')
  [ -n "$lines" ] || lines=0

  printf '%sПовний поточний звіт (%s рядків):%s\n' "$c_cyan" "$lines" "$c_reset"
  hr
  cat "$REPORT"
  hr

  if [ "$lines" -le 3 ] 2>/dev/null; then
    printf 'У цьому запуску ще не завершено жодної перевірки, тому звіт містить лише заголовок.\n'
  fi
}

about_hits() {
  cat <<'EOF'
Як трактувати результати:

Сильний сигнал:
  • модифікація лежить в активній mods/instance;
  • вона згадується у latest.log/debug.log як реально завантажена;
  • відповідний JAR/бібліотека відкрита процесом Minecraft;
  • збігаються кілька незалежних джерел.

Слабкий сигнал:
  • одне слово/назва;
  • файл у Downloads, backup або старому архіві;
  • загальні слова на кшталт chest/future/eclipse/winner;
  • rm/curl/wget у shell history;
  • звичайний USB disconnect або restart журналу.
EOF
}

choose_language() {
  case "$LANGUAGE" in uk|ru|en) ;; *) LANGUAGE=uk ;; esac
  [ -t 0 ] || return 0

  clear_screen
  ui_title
  printf 'Оберіть мову / Выберите язык / Select language:\n'
  printf '[1] Українська\n[2] Русский\n[3] English\n'
  case "$LANGUAGE" in ru) default=2 ;; en) default=3 ;; *) default=1 ;; esac
  printf '1-3 [%s]: ' "$default"
  IFS= read -r choice
  case "$choice" in
    2|ru|RU) LANGUAGE=ru ;;
    3|en|EN) LANGUAGE=en ;;
    1|uk|UK|'') LANGUAGE=uk ;;
    *) printf 'Unknown choice; Ukrainian selected.\n'; LANGUAGE=uk ;;
  esac
}

print_menu() {
  case "$LANGUAGE" in
    ru) cat <<'EOF'
[1]  Проверка совместимости команд
[2]  Информация о системе / дисках / сети
[3]  Поиск подозрительных JAR/ZIP/SO/DLL/DYLIB
[4]  Поиск конфигов и текстовых следов за 14 дней
[5]  Папки Minecraft / launcher
[6]  Активные папки mods
[7]  Имена пользователей в Minecraft-логах
[8]  Recent / Корзина / Downloads
[9]  Базы истории и установленные браузеры
[10] Java/Minecraft процессы + библиотеки + сеть
[11] Опциональный memory strings scan
[12] Shell history
[13] Автозапуск / persistence
[14] USB / system logs
[15] Сравнить активные моды с baseline
[16] Глубокий scan всего HOME (может быть долгим)
[17] Linux execution traces / loaded modules
[18] Linux package/install history
[19] Анализ содержимого активных Minecraft JAR
[20] Создать baseline SHA-256 активных модов
[21] Полное сканирование
[22] Показать текущий отчёт
[23] Как трактовать результаты
[0]  Выход
EOF
      ;;
    en) cat <<'EOF'
[1]  Command compatibility check
[2]  System / disks / network information
[3]  Search suspicious JAR/ZIP/SO/DLL/DYLIB
[4]  Search configs and text traces from the last 14 days
[5]  Minecraft / launcher folders
[6]  Active mods folders
[7]  Usernames in Minecraft logs
[8]  Recent / Trash / Downloads
[9]  Browser history databases and installed browsers
[10] Java/Minecraft processes + libraries + network
[11] Optional memory strings scan
[12] Shell history
[13] Autostart / persistence
[14] USB / system logs
[15] Compare active mods with baseline
[16] Deep scan of all HOME (may take a long time)
[17] Linux execution traces / loaded modules
[18] Linux package/install history
[19] Inspect active Minecraft JAR contents
[20] Create active-mod SHA-256 baseline
[21] Full scan
[22] Show current report
[23] How to interpret results
[0]  Exit
EOF
      ;;
    *) cat <<'EOF'
[1]  Перевірка сумісності команд
[2]  Інформація про систему / диски / мережу
[3]  Пошук підозрілих JAR/ZIP/SO/DLL/DYLIB
[4]  Пошук конфігів і текстових слідів за 14 днів
[5]  Minecraft / launcher папки
[6]  Активні mods-папки
[7]  Імена користувачів у Minecraft-логах
[8]  Recent / Trash / Downloads
[9]  Бази історії та встановлені браузери
[10] Java/Minecraft процеси + бібліотеки + мережа
[11] Опціональний memory strings scan
[12] Shell history
[13] Автозапуск / persistence
[14] USB / system logs
[15] Порівняти активні моди з baseline
[16] Глибокий scan усього HOME (може бути довгим)
[17] Linux execution traces / loaded modules
[18] Linux package/install history
[19] Аналіз вмісту активних Minecraft JAR
[20] Створити baseline SHA-256 активних модів
[21] Повне сканування
[22] Показати поточний звіт
[23] Як трактувати результати
[0]  Вихід
EOF
      ;;
  esac
}

menu() {
  while :
  do
    header
    print_menu
    case "$LANGUAGE" in
      ru) legend='Красный = сигнал  |  Жёлтый = пропуск  |  Голубой = раздел'; prompt='Выбери пункт:' ;;
      en) legend='Red = lead  |  Yellow = skipped  |  Blue = section'; prompt='Select an item:' ;;
      *)  legend='Червоний = сигнал  |  Жовтий = пропуск  |  Блакитний = розділ'; prompt='Обери пункт:' ;;
    esac
    printf '%s%s%s\n' "$c_dim" "$legend" "$c_reset"
    printf '%s%s%s\n' "$c_cyan" '────────────────────────────────────────────────────────────────' "$c_reset"
    printf '%s%s%s ' "$c_bold" "$prompt" "$c_reset"
    IFS= read -r choice

    case "$choice" in
      1) compatibility_check; pause_menu ;;
      2) system_info; pause_menu ;;
      3) search_banned_files; pause_menu ;;
      4) search_configs; pause_menu ;;
      5) minecraft_locations; pause_menu ;;
      6) active_mods; pause_menu ;;
      7) twinks_from_logs; pause_menu ;;
      8) recent_activity; pause_menu ;;
      9) browser_history_locations; pause_menu ;;
      10) java_processes; pause_menu ;;
      11) memory_scan; pause_menu ;;
      12) shell_history; pause_menu ;;
      13) persistence; pause_menu ;;
      14) usb_logs; pause_menu ;;
      15) compare_mod_baseline; pause_menu ;;
      16) deep_scan_home; pause_menu ;;
      17) linux_execution_traces; pause_menu ;;
      18) linux_package_history; pause_menu ;;
      19) scan_active_archive_contents; pause_menu ;;
      20) create_mod_baseline; pause_menu ;;
      21) full_scan; pause_menu ;;
      22) show_report; pause_menu ;;
      23) about_hits; pause_menu ;;
      0)
        printf 'Звіт: %s\n' "$REPORT"
        exit 0
        ;;
      *)
        echo "Невідомий пункт"
        ;;
    esac
  done
}

if [ "$PLATFORM" = "unknown" ]; then
  echo "Непідтримувана ОС: $OS"
  echo "Підтримуються Linux та macOS."
  exit 1
fi

choose_language
printf 'Veritas AC start: %s\nPlatform: %s\nLanguage: %s\nStatus: sections are appended after each completed check\n' \
  "$(date 2>/dev/null)" "$PLATFORM" "$LANGUAGE" > "$REPORT"

menu
