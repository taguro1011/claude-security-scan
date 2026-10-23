"""このWindows本体の設定チェック（管理者権限不要の範囲）。

情報集めは windows_probe.ps1（読み取りだけ）が JSON で返し、ここで重要度と直し方を決める。
秘密になりうる値（自動ログオンのパスワード・常駐の起動引数）は受け取っても記録しない。
"""
from __future__ import annotations

import json
import ntpath
import os
import re
from datetime import date
from pathlib import Path

from .common import WHOLE, Result, powershell, redact, run, short_err

M = "windows"
PC = "このPC"
PROBE = Path(__file__).with_name("windows_probe.ps1")

# Windows の更新終了日（Home/Pro, Enterprise/Education）。Microsoft のライフサイクル情報より。
# Windows 10 は 2025-10-14 に終了（ESU 登録時のみ更新が続く）。新しいバージョンが出たらここに足す
EOS = {
    22000: ("2023-10-10", "2024-10-08"),  # 11 21H2
    22621: ("2024-10-08", "2025-10-14"),  # 11 22H2
    22631: ("2025-11-11", "2026-11-10"),  # 11 23H2
    26100: ("2026-10-13", "2027-10-12"),  # 11 24H2
    26200: ("2027-10-12", "2028-10-10"),  # 11 25H2
}
# 36か月サポートの版（Pro Education は Home/Pro と同じ24か月なので含めない）
LONG_SUPPORT_EDITIONS = re.compile(r"^(Enterprise|Education|IoTEnterprise)N?$")
WIN10_EOS = "2025-10-14"
UPDATE_STALE_DAYS = 45
PENDING_GRACE_DAYS = 14

PROFILE_JA = {"Domain": "ドメイン", "Private": "プライベート", "Public": "パブリック"}
BROAD_JA = {"S-1-1-0": "Everyone", "S-1-5-32-545": "Users", "S-1-5-11": "Authenticated Users", "S-1-5-7": "Anonymous"}
# OS が標準で開けているポート（RPC・ファイル共有・配信最適化など）はファイアウォール前提で数えない
SYSTEM_PROCS = {"system", "idle", "svchost", "lsass", "wininit", "services", "spoolsv"}
RISKY_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 1433: "SQL Server", 3306: "MySQL", 3389: "リモートデスクトップ",
               5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 27017: "MongoDB"}
SUSPICIOUS_DIRS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\", "\\users\\public\\", "\\$recycle.bin\\")
SCRIPT_HOSTS = {"mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"}
SECURITY_CATEGORIES = {"0fa1201d-4330-4fa8-8ae9-b877473b6441", "e6cf1350-c01b-414d-a61f-263d14d133b4"}  # セキュリティ / 重要
DEFINITION_CATEGORY = "e0789628-ce08-4437-be74-2495b842f43b"  # 定義ファイル（Defender が自分で更新する）

# 確認できなかったときに「解消」「新規」から外す範囲（finding のタイトルに含む文字列）
BLOCKS = {
    "os": ["サポートが終了", "Windows 10"], "last_update": ["更新が"], "bitlocker": ["ディスク暗号化"],
    "defender": ["ウイルス対策", "定義ファイル", "改ざん防止"], "firewall": ["ファイアウォール"], "uac": ["UAC", "ユーザーアカウント制御"],
    "autologon": ["自動ログオン"], "screenlock": ["サインインを求めない"], "listening": ["外部から接続"],
    "rdp": ["リモートデスクトップ"], "smb1": ["SMBv1"], "secureboot": ["セキュアブート"], "accounts": ["管理者", "Guest"],
    "secret_files": ["秘密鍵", "秘密情報", "AWS", "Git"], "startup": ["常駐"], "pending_updates": ["未適用"],
}
ITEM_JA = {
    "os": "Windowsのバージョン", "last_update": "最後の更新日", "bitlocker": "ディスク暗号化", "defender": "ウイルス対策",
    "av_products": "ウイルス対策製品", "fw_products": "ファイアウォール製品", "firewall": "ファイアウォール", "uac": "UAC",
    "autologon": "自動ログオン", "screenlock": "画面ロック", "listening": "待ち受けポート", "rdp": "リモートデスクトップ",
    "smb1": "SMBv1", "secureboot": "セキュアブート", "accounts": "アカウント", "secret_files": "秘密情報ファイル",
    "startup": "常駐プログラム", "tasks": "タスクスケジューラ", "pending_updates": "Windows Update",
}


def _probe(part: str, timeout: int):
    exe = powershell()  # PATH ではなく System32 の本物を使う
    if not os.path.isfile(exe):
        return None, "Windows PowerShell が見つからない"
    rc, out, err = run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(PROBE), "-Part", part], timeout)
    # 標準出力には常駐の起動コマンド等が入るので、失敗時も標準エラーだけを理由として残す
    start = out.find("{")
    if start >= 0:
        try:
            return json.loads(out[start:]), ""
        except json.JSONDecodeError:
            pass
    return None, short_err(err.strip()[-400:]) or f"終了コード {rc}（出力を解釈できない）"


def scan(cfg: dict) -> Result:
    c = cfg.get("windows", {})
    data, err = _probe("base", c.get("timeout", 300))
    r = Result()
    if not isinstance(data, dict):
        r.cov(M, "Windows本体", "error", err or "情報を取得できない", blocks=WHOLE)
        return r
    evaluate(r, data)
    if c.get("check_updates", True):
        upd, err = _probe("updates", c.get("updates_timeout", 300))
        if isinstance(upd, dict):
            evaluate(r, upd)
        else:
            _err(r, "pending_updates", err or "情報を取得できない")
    return r


def _err(r: Result, key: str, msg: str):
    if key == "tasks":  # タスクスケジューラだけ読めなかった → その種類の常駐だけ比較から外す
        blocks = [("常駐", KIND_JA["task"])]
    else:
        blocks = [(t, "") for t in BLOCKS.get(key, [ITEM_JA.get(key, key)])]
    r.cov(M, ITEM_JA.get(key, key), "error", short_err(msg), blocks=blocks)


def evaluate(r: Result, data: dict, today: date | None = None):
    """probe の JSON から指摘を作る。テストしやすいよう Windows 以外でも動く純粋な関数にしてある。"""
    errs = data.get("errors") or {}
    for k, msg in errs.items():
        if k in ("av_products", "fw_products"):  # 製品一覧は補助情報。読めないときは本体の判定側で「判定不能」にする
            r.cov(M, ITEM_JA[k], "error", short_err(str(msg)), blocks=[])
        else:
            _err(r, k, str(msg))
    av_known, fw_known = "av_products" not in errs, "fw_products" not in errs
    checks = [
        ("os", lambda v: _os(r, v, data.get("last_update"), today or date.today())),
        ("last_update", lambda v: _last_update(r, v, today or date.today())),
        ("bitlocker", lambda v: _bitlocker(r, v)),
        ("defender", lambda v: _defender(r, v, _list(data.get("av_products")) or [], av_known)),
        ("firewall", lambda v: _firewall(r, v, _list(data.get("fw_products")) or [], fw_known)),
        ("uac", lambda v: _uac(r, v)),
        ("autologon", lambda v: _autologon(r, v)),
        ("screenlock", lambda v: _screenlock(r, v)),
        ("listening", lambda v: _listening(r, v)),
        ("rdp", lambda v: _rdp(r, v)),
        ("smb1", lambda v: _smb1(r, v)),
        ("secureboot", lambda v: _secureboot(r, v)),
        ("accounts", lambda v: _accounts(r, v)),
        ("secret_files", lambda v: _secret_files(r, v)),
        ("startup", lambda v: _startup(r, v)),
        ("pending_updates", lambda v: _pending(r, v)),
    ]
    for key, fn in checks:
        if key not in data or key in errs:
            continue
        val = data[key]
        if key in LIST_KEYS:
            val = _list(val)
            if val is None:
                _err(r, key, "想定外の形式で返った")
                continue
        fn(val)
    if "defender" in errs and av_known and "av_products" in data:  # Defender を読めなくても他社製品の状態で判定できる
        _av_products_only(r, _list(data.get("av_products")) or [])


LIST_KEYS = {"firewall", "listening", "startup", "pending_updates"}


def _list(v):
    """PowerShell 5.1 の ConvertTo-Json は配列を {"value": [...], "Count": n} で包むことがあるので戻す。"""
    if v is None:
        return []
    if isinstance(v, dict) and isinstance(v.get("value"), list):
        return v["value"]
    if isinstance(v, dict):
        return [v]  # 要素1つの配列が素のオブジェクトになった場合
    return v if isinstance(v, list) else None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---- OS・更新 -------------------------------------------------------------

def _os(r: Result, v: dict | None, last: dict | None, today: date):
    if not v or not v.get("build"):
        r.cov(M, ITEM_JA["os"], "error", "ビルド番号を読めない", blocks=[(t, "") for t in BLOCKS["os"]])
        return
    build, ed = int(v["build"]), str(v.get("edition") or "")
    label = f"ビルド {build}.{v.get('ubr') or 0}" + (f"（{v['display']}）" if v.get("display") else "") + (f" / {ed}" if ed else "")
    if ed.endswith("S") or "Server" in ed:  # LTSC・Server はサポート期間の体系が別
        r.cov(M, ITEM_JA["os"], "ok", f"{label}（LTSC/Serverは対象外）")
        return
    recent = _days_since(last, today)
    if build < 22000:
        if today.isoformat() <= WIN10_EOS:
            r.cov(M, ITEM_JA["os"], "ok", label)
            return
        esu = recent is not None and recent <= UPDATE_STALE_DAYS
        r.add(M, "medium" if esu else "high", "Windows 10（サポートが終了したOS）", PC,
              label + ("\n最近も更新が入っているので、ESU（延長セキュリティ更新）に登録済みと思われます" if esu else
                       "\n最近の更新が見当たらない＝セキュリティ修正が届いていない可能性が高い"),
              "Windows 11 へアップグレードする。すぐ無理なら 設定 → Windows Update で ESU（延長セキュリティ更新）に登録する",
              key="w-os-win10")
        return
    ends = EOS.get(build)
    if not ends:
        r.cov(M, ITEM_JA["os"], "ok", label)
        return
    end = ends[1] if LONG_SUPPORT_EDITIONS.match(ed) else ends[0]
    if today.isoformat() > end:
        r.add(M, "high", f"サポートが終了したWindows 11のバージョン（{v.get('display') or build}）", PC,
              f"{label}\n更新終了日 {end}。これ以降セキュリティ修正が届かない",
              "設定 → Windows Update →「最新の更新プログラムが利用可能になったらすぐに入手する」をオンにして、新しいバージョン（25H2 など）へ更新する（無料）",
              key="w-os-eos")
    else:
        r.cov(M, ITEM_JA["os"], "ok", f"{label}（更新終了 {end}）")


def _days_since(last: dict | None, today: date) -> int | None:
    try:
        return (today - date.fromisoformat(str(last["date"]))).days
    except (TypeError, KeyError, ValueError):
        return None


def _last_update(r: Result, v: dict | None, today: date):
    days = _days_since(v, today)
    if days is None:
        r.cov(M, ITEM_JA["last_update"], "error", "更新履歴を読めない", blocks=[("更新が", "")])
    elif days > UPDATE_STALE_DAYS:
        r.add(M, "high" if days > 90 else "medium", "Windowsの更新が長く適用されていない", PC,
              f"最後の更新: {v['date']}（{v.get('kb', '')}・{days}日前）",
              "設定 → Windows Update →「更新プログラムのチェック」を実行し、再起動まで済ませる", key="w-update-age")
    else:
        r.cov(M, ITEM_JA["last_update"], "ok", f"{v['date']}（{days}日前）")


def _pending(r: Result, items: list | None):
    items = [u for u in (items or []) if isinstance(u, dict)]
    real = [u for u in items if DEFINITION_CATEGORY not in (u.get("categories") or [])]
    if not real:
        r.cov(M, ITEM_JA["pending_updates"], "ok", "未適用なし" if not items else "定義ファイルのみ（自動で入る）")
        return
    sec = [u for u in real if SECURITY_CATEGORIES & set(u.get("categories") or []) or u.get("msrc") in ("Critical", "Important")]
    # 配信から2週間以上たっても入っていないセキュリティ更新だけを「高」にする（月例の直後に毎回鳴らさない）
    stale = [u for u in sec if (_days_since({"date": u.get("released")}, date.today()) or 999) >= PENDING_GRACE_DAYS]
    r.add(M, "high" if stale else "medium", "未適用のWindows更新プログラムがある", PC,
          "\n".join(str(u.get("title", "")) for u in real[:15]) + (f"\nほか{len(real) - 15}件" if len(real) > 15 else ""),
          "設定 → Windows Update から適用する（再起動が必要なものは作業の区切りで）", key="w-pending")


# ---- 暗号化・ウイルス対策・ファイアウォール --------------------------------

# エクスプローラーの BitLocker 表示（System.Volume.BitLockerProtection）の値。実機で要確認
SHELL_BITLOCKER = {1: "on", 3: "on", 6: "on", 2: "off", 4: "decrypting", 5: "suspended", 8: "waiting"}  # 3 は「暗号化中」


def _bitlocker(r: Result, v: dict | None):
    v = v or {}
    drive = v.get("drive") or "C:"
    state = None
    if v.get("source") == "cmdlet":  # 管理者で実行したとき
        vol = str(v.get("volume") or "")
        if str(v.get("protection")) == "On" or vol == "EncryptionInProgress":
            state = "on"
        elif vol == "FullyDecrypted":
            state = "off"
        elif vol == "DecryptionInProgress":
            state = "decrypting"
        elif vol == "FullyEncrypted":
            state = "suspended"  # 暗号化済みなのに保護オフ＝一時停止 or 有効化待ち（非管理者時の判定とそろえる）
    elif v.get("source") == "shell":
        state = SHELL_BITLOCKER.get(_int(v.get("shell")))
    target = f"{PC} {drive}"
    fix = ("Pro: コントロールパネル → BitLocker ドライブ暗号化 で有効にする。Home: 設定 → プライバシーとセキュリティ → デバイスの暗号化 をオン。"
           "回復キーが Microsoft アカウント等に保存されているか必ず確認する")
    if state == "on":
        r.cov(M, ITEM_JA["bitlocker"], "ok", drive)
    elif state == "off":
        r.add(M, "critical", "ディスク暗号化（BitLocker / デバイスの暗号化）がオフ", target,
              "盗難・紛失時に、ディスクを取り出すだけで全データが読まれる", fix)
    elif state in ("suspended", "decrypting", "waiting"):
        why = {"suspended": "一時停止中（鍵が平文で置かれ、暗号化が効いていない状態）",
               "decrypting": "暗号化を解除している途中",
               "waiting": "有効化待ち（データは暗号化されているが鍵が保護されておらず、実質オフ）"}[state]
        r.add(M, "high", f"ディスク暗号化が効いていない（{why.split('（')[0]}）", target, why, fix)
    else:
        r.cov(M, ITEM_JA["bitlocker"], "error",
              "状態を判定できない（暗号化に対応していないPC、または管理者権限が必要）。設定 → プライバシーとセキュリティ で確認してください",
              blocks=[("ディスク暗号化", "")])


def _av_state(p: dict) -> tuple[bool, bool]:
    """Security Center の productState → (有効か, 定義が古いか)。"""
    s = _int(p.get("state")) or 0
    return ((s >> 12) & 0xF) == 1, ((s >> 4) & 0xF) == 1


def _third_party(products: list) -> list[str]:
    return [str(p.get("name")) for p in products if isinstance(p, dict) and _av_state(p)[0]
            and not re.search(r"Windows Defender|Microsoft Defender", str(p.get("name")), re.I)]


def _defender(r: Result, v: dict | None, av: list, av_known: bool = True):
    v = v or {}
    other = _third_party(av)
    if not (v.get("av") and v.get("realtime")) and not other and not av_known:
        r.cov(M, ITEM_JA["defender"], "error", "Defender が止まっているが、他社製ウイルス対策の有無を確認できない",
              blocks=[("ウイルス対策", "")])
        return
    fix = "Windows セキュリティ → ウイルスと脅威の防止 → 設定の管理 →「リアルタイム保護」をオンにする"
    if v.get("av") and v.get("realtime"):
        r.cov(M, ITEM_JA["defender"], "ok", "Microsoft Defender")
        age = _int(v.get("sig_age"))
        if age is not None and age > 7:
            r.add(M, "medium", "ウイルス対策の定義ファイルが古い", PC, f"{age}日前のまま",
                  "Windows セキュリティ → ウイルスと脅威の防止 →「保護の更新」から更新する", key="w-sig-age")
        if v.get("tamper") is False:
            r.add(M, "low", "ウイルス対策の改ざん防止がオフ", PC, "マルウェアに Defender を止められやすい",
                  "Windows セキュリティ → ウイルスと脅威の防止 → 設定の管理 →「改ざん防止」をオン")
    elif other:
        r.cov(M, ITEM_JA["defender"], "ok", "他社製品が有効: " + ", ".join(other))
        _av_outdated(r, av)
    elif "passive" in str(v.get("mode", "")).lower():
        r.add(M, "critical", "ウイルス対策が動いていない", PC,
              "Defender はパッシブモード（他社製品に任せる設定）だが、有効な他社製品が見当たらない", fix)
    else:
        r.add(M, "critical", "ウイルス対策のリアルタイム保護がオフ", PC,
              f"Defender: サービス={v.get('service')} / ウイルス対策={v.get('av')} / リアルタイム保護={v.get('realtime')}", fix)


def _av_outdated(r: Result, av: list):
    old = [str(p.get("name")) for p in av if isinstance(p, dict) and all(_av_state(p))]
    if old:
        r.add(M, "medium", "ウイルス対策の定義ファイルが古い", PC, ", ".join(old), "その製品の画面から定義ファイルを更新する", key="w-sig-age")


def _av_products_only(r: Result, av: list):
    on = [str(p.get("name")) for p in av if isinstance(p, dict) and _av_state(p)[0]]
    if on:
        r.cov(M, ITEM_JA["defender"] + "（製品一覧）", "ok", ", ".join(on))
        _av_outdated(r, av)
    elif av:
        r.add(M, "critical", "ウイルス対策が動いていない", PC, "登録されたウイルス対策製品がすべて無効",
              "Windows セキュリティ → ウイルスと脅威の防止 でリアルタイム保護をオンにする")


def _firewall(r: Result, profiles: list | None, products: list, fw_known: bool = True):
    profiles = [p for p in (profiles or []) if isinstance(p, dict)]
    if not profiles:
        r.cov(M, ITEM_JA["firewall"], "error", "プロファイルを読めない", blocks=[("ファイアウォール", "")])
        return
    off = [p["name"] for p in profiles if str(p.get("enabled")).lower() in ("false", "0")]
    other = _third_party(products)
    if not off:
        r.cov(M, ITEM_JA["firewall"], "ok", "全プロファイル有効")
    elif other:
        r.cov(M, ITEM_JA["firewall"], "ok", "Windows ファイアウォールの一部がオフだが他社製品が有効: " + ", ".join(other))
    elif not fw_known:
        r.cov(M, ITEM_JA["firewall"], "error", "Windows ファイアウォールの一部がオフだが、他社製ファイアウォールの有無を確認できない",
              blocks=[("ファイアウォール", "")])
    else:
        names = "・".join(PROFILE_JA.get(n, n) for n in off)
        r.add(M, "high" if "Public" in off else "medium", f"ファイアウォールがオフ（{names}）", PC,
              "オフのネットワークの種類: " + names + "（パブリック＝カフェ・ホテル等の公衆Wi-Fi）",
              "Windows セキュリティ → ファイアウォールとネットワーク保護 → オフになっているネットワークをオンにする")


# ---- サインイン・UAC ------------------------------------------------------

def _uac(r: Result, v: dict | None):
    v = v or {}
    lua, admin, secure = _int(v.get("lua")), _int(v.get("admin")), _int(v.get("secure"))
    fix = "コントロールパネル → ユーザーアカウント →「ユーザーアカウント制御設定の変更」で既定（上から2番目）に戻す（変更には管理者権限が必要）"
    if lua == 0:
        r.add(M, "high", "ユーザーアカウント制御（UAC）が無効", PC, "マルウェアが確認なしで管理者権限を得られる", fix)
        return
    if admin == 0:
        r.add(M, "medium", "UACの確認が出ない設定（管理者操作が無確認で通る）", PC, "ConsentPromptBehaviorAdmin = 0", fix)
    if secure == 0:
        r.add(M, "low", "UACの確認画面が保護されたデスクトップに出ない", PC, "PromptOnSecureDesktop = 0", fix)
    if lua != 0 and admin != 0 and secure != 0:
        r.cov(M, ITEM_JA["uac"], "ok")


def _autologon(r: Result, v: dict | None):
    v = v or {}
    if v.get("has_password"):
        r.add(M, "critical", "自動ログオンのパスワードがレジストリに平文で保存されている", PC,
              "Winlogon の DefaultPassword に値がある（値は表示しない）。このPCの他のユーザーやマルウェアが読める",
              "管理者で regedit → HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon の DefaultPassword を削除し、AutoAdminLogon を 0 にする。そのパスワードは変更する")
    if str(v.get("enabled")) == "1":
        r.add(M, "high", "自動ログオンが有効", PC, f"ユーザー: {v.get('user') or '?'}",
              "Win+R → netplwiz →「ユーザーがこのコンピューターを使うには、ユーザー名とパスワードの入力が必要」にチェック"
              "（項目が無い場合は 設定 → アカウント → サインイン オプション の「Windows Hello サインインのみを許可する」を一度オフ）")
    elif not v.get("has_password"):
        r.cov(M, ITEM_JA["autologon"], "ok")


def _screenlock(r: Result, v: dict | None):
    v = v or {}
    delay = _int(v.get("delay_lock"))
    if delay is not None:  # Modern Standby のPC（設定の「再度サインインを求めるタイミング」がこの値）
        if delay in (0xFFFFFFFF, -1):  # 「しない」。レジストリの DWORD は PowerShell から -1 で読める
            r.add(M, "medium", "スリープ復帰時にサインインを求めない設定", PC, "「再度サインインを求めるタイミング」が「しない」",
                  "設定 → アカウント → サインイン オプション →「しばらく操作しなかった場合に再度サインインを求めるタイミング」を「PCのスリープを解除する時間」などにする。離席時は Win+L")
        else:
            r.cov(M, ITEM_JA["screenlock"], "ok", "スリープ復帰時にサインインを要求")
        return
    ac = _int(v.get("pol_wake_ac")) if v.get("pol_wake_ac") is not None else _int(v.get("wake_ac"))
    dc = _int(v.get("pol_wake_dc")) if v.get("pol_wake_dc") is not None else _int(v.get("wake_dc"))
    if ac == 0 or dc == 0:
        when = "・".join(x for x, val in (("電源接続時", ac), ("バッテリー時", dc)) if val == 0)
        r.add(M, "medium", "スリープ復帰時にサインインを求めない設定", PC, f"{when}は、スリープから戻るとそのまま使える",
              "設定 → アカウント → サインイン オプション →「しばらく操作しなかった場合に再度サインインを求めるタイミング」を「PCのスリープを解除する時間」などにする。離席時は Win+L")
        return
    if ac is not None or dc is not None:
        r.cov(M, ITEM_JA["screenlock"], "ok", "スリープ復帰時にサインインを要求")
        return
    act = str(v.get("pol_active") or v.get("ss_active") or "")
    sec = str(v.get("pol_secure") or v.get("ss_secure") or "")
    if act == "1" and sec == "1":
        r.cov(M, ITEM_JA["screenlock"], "ok", "スクリーンセーバーでロック")
    else:
        r.cov(M, ITEM_JA["screenlock"], "error", "スリープ復帰時の設定を判定できない", blocks=[("サインインを求めない", "")])


# ---- ネットワーク ---------------------------------------------------------

def _is_local(addr: str) -> bool:
    return addr.startswith("127.") or addr in ("::1", "localhost")


def _listening(r: Result, items: list | None):
    exposed: dict[int, set[str]] = {}
    skipped = 0
    for it in items or []:
        if not isinstance(it, dict) or _is_local(str(it.get("addr", ""))):
            continue
        port, proc = _int(it.get("port")), str(it.get("proc") or "?")
        if port is None:
            continue
        if proc.lower() in SYSTEM_PROCS and port not in RISKY_PORTS:
            skipped += 1
            continue
        exposed.setdefault(port, set()).add(proc)
    for port, procs in sorted(exposed.items()):
        name = RISKY_PORTS.get(port)
        r.add(M, "medium" if name else "low", f"外部から接続を受け付けるポート {port}" + (f"（{name}）" if name else ""), f"tcp/{port}",
              "プロセス: " + ", ".join(sorted(procs)),
              "使っていないサーバー機能・開発サーバーなら止めるか 127.0.0.1 にバインドする。公衆Wi-Fiでは特に注意")
    r.cov(M, ITEM_JA["listening"], "ok", f"OS標準の待ち受け {skipped}件は対象外（ファイアウォール前提）")


def _rdp(r: Result, v: dict | None):
    v = v or {}
    deny = _int(v.get("pol_deny")) if v.get("pol_deny") is not None else _int(v.get("deny"))
    if deny != 0:
        r.cov(M, ITEM_JA["rdp"], "ok", "無効")
        return
    port = _int(v.get("port")) or 3389
    if _int(v.get("nla")) == 0:
        r.add(M, "high", "リモートデスクトップがネットワークレベル認証（NLA）なしで有効", PC, f"ポート {port}",
              "設定 → システム → リモートデスクトップ →「接続にネットワークレベル認証を使用するようにコンピューターに要求する」をオン。使っていなければリモートデスクトップ自体をオフ")
    else:
        r.add(M, "medium", "リモートデスクトップが有効", PC, f"ポート {port}（NLA あり）",
              "使っていなければ 設定 → システム → リモートデスクトップ をオフ。使うなら強いパスワードと、社外からはVPN経由に限定する")


def _smb1(r: Result, v: dict | None):
    v = v or {}
    on = []
    if v.get("client_present") and _int(v.get("client_start")) != 4:
        on.append("クライアント")
    server = _int(v.get("server"))
    if server == 1 or (server != 0 and v.get("server_present") and _int(v.get("server_start")) != 4):
        on.append("サーバー")
    if on:
        r.add(M, "high", "SMBv1（古いファイル共有の仕組み）が有効", PC, "有効: " + "・".join(on) + "（WannaCry などが悪用した古い方式）",
              "コントロールパネル → プログラムと機能 →「Windows の機能の有効化または無効化」→「SMB 1.0/CIFS ファイル共有のサポート」のチェックを外す。古い複合機・NASが使っていないか先に確認")
    else:
        r.cov(M, ITEM_JA["smb1"], "ok", "無効")


def _secureboot(r: Result, v: dict | None):
    if v is None or v.get("enabled") is None:
        r.cov(M, ITEM_JA["secureboot"], "skip", "UEFI のセキュアブート情報が無い（古いBIOS方式か仮想マシン）", blocks=[("セキュアブート", "")])
    elif _int(v.get("enabled")) == 0:
        r.add(M, "medium", "セキュアブートがオフ", PC, "起動時に不正なプログラムを読み込まれる余地がある",
              "PC起動時の UEFI（BIOS）設定でセキュアブートを有効にする（手順はPCメーカーのサポートページを確認）")
    else:
        r.cov(M, ITEM_JA["secureboot"], "ok")


def _accounts(r: Result, v: dict | None):
    v = v or {}
    if v.get("guest_enabled"):
        r.add(M, "medium", "Guestアカウントが有効", PC, "パスワード無しで使える共用アカウント",
              "管理者のコマンドプロンプトで net user Guest /active:no を本人が実行する")
    if v.get("is_admin"):
        r.add(M, "low", "普段使いのアカウントが管理者", PC, "マルウェアを実行してしまったときの被害が大きくなる",
              "管理作業用の管理者アカウントを別に作り、普段使いのアカウントは「標準ユーザー」にする")
    if not v.get("guest_enabled") and not v.get("is_admin"):
        r.cov(M, ITEM_JA["accounts"], "ok")


def _broad(sids) -> str:
    return "・".join(BROAD_JA.get(s, s) for s in sids or [])


def _secret_files(r: Result, v: dict | None):
    v = v or {}
    for k in v.get("ssh_keys") or []:
        if k.get("broad"):
            r.add(M, "high", "SSH秘密鍵が他のユーザーからも読める", str(k.get("path")), "読み取りを許しているグループ: " + _broad(k["broad"]),
                  f'icacls "{k.get("path")}" /inheritance:r /grant:r "%USERNAME%:F" で本人だけにする（OpenSSH はこの状態でないと鍵を使えないこともある）')
    n = _int(v.get("authorized_keys")) or 0
    if n:
        r.add(M, "info", "このPCへSSHログインできる公開鍵が登録されている", str(Path.home() / ".ssh" / "authorized_keys"), f"{n}件",
              "心当たりのない鍵があれば削除する（OpenSSH サーバーを動かしていなければ影響なし）")
    for f in v.get("files") or []:
        name, path = str(f.get("name")), str(f.get("path"))
        if f.get("broad"):
            r.add(M, "medium", "秘密情報を含むファイルが他のユーザーからも読める", path, "読み取りを許しているグループ: " + _broad(f["broad"]),
                  f'icacls "{path}" /inheritance:r /grant:r "%USERNAME%:F" で本人だけにする')
        if name.endswith("credentials") and name.startswith(".aws"):
            r.add(M, "medium", "AWSの長期アクセスキーファイルが存在する", path, "SSOを使っている環境では通常不要",
                  "中身のキーが使われていないかIAMで確認し、不要なら無効化→ファイル削除。SSO(aws sso login)へ寄せる")
        elif name == ".git-credentials":
            r.add(M, "medium", "Gitのパスワード・トークンが平文ファイルに保存されている", path, "git config の credential.helper=store による保存",
                  "git config --global credential.helper manager（Git for Windows 同梱の資格情報マネージャー）に切り替え、トークンを再発行してからファイルを削除")


# ---- 常駐 -----------------------------------------------------------------

KIND_JA = {"run": "自動起動（レジストリ）", "startup": "スタートアップフォルダ", "task": "タスクスケジューラ", "service": "サービス"}
_EXE_END = re.compile(r"(?i)\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|dll|lnk)(?=[\s,]|$)")
_ENCODED = re.compile(r"(?i)(^|\s)[-/]e(c|n[a-z]*)?(\s|$)")  # -e / -ec / -enc / -EncodedCommand（-ex は対象外）
_ARGISH = re.compile(r"\s[-/]|=")


def split_cmd(cmd: str) -> tuple[str, str, bool]:
    """コマンドライン → (実行ファイル, 引数, 引用符なしで空白を含むパスか)。引数は判定にだけ使い、記録しない。"""
    s = (cmd or "").strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return s[1:end], s[end + 1:], False
        s = s[1:]  # 閉じ引用符が無い → 引用符なしと同じに扱う
    first = (s.split() or [""])[0]
    m = _EXE_END.search(s)
    exe = s[:m.end()] if m else first
    # 拡張子の手前に「 -x」「 /x」「=」がある＝引数まで巻き込んでいるので、最初の区切りまでに留める（秘密を記録しないため）
    # 空白入りのパスを許すのは「C:\」「\\server」で始まる絶対パスだけ（mshta http://... のような形は先頭の語が実行ファイル）
    if _ARGISH.search(exe) or "://" in exe or (" " in exe and not re.match(r"^([A-Za-z]:\\|\\\\)", exe)):
        exe = first
    return exe, s[len(exe):], " " in exe


def _startup(r: Result, items: list | None):
    r.cov(M, ITEM_JA["startup"], "ok", f"{len(items or [])}件（管理者権限なしでは、SYSTEMや他ユーザーのタスクの一部が見えないことがある）")
    for it in items or []:
        if not isinstance(it, dict):
            continue
        kind, where, name = str(it.get("kind")), str(it.get("where") or ""), str(it.get("name") or "?")
        exe, args, unquoted = split_cmd(str(it.get("cmd") or ""))
        low = exe.lower()
        base = ntpath.basename(low)
        if base and "." not in base:
            base += ".exe"  # 「powershell -enc ...」のように拡張子なしで書かれた場合
        account = str(it.get("account") or "")
        system = kind == "service" and account.lower() in ("", "localsystem", "nt authority\\system")
        sev, note = "info", ""
        if any(d in low for d in SUSPICIOUS_DIRS):
            sev, note = "high", "一時フォルダ・Downloads・Public などから起動している常駐。マルウェアの典型パターン"
        elif base in ("powershell.exe", "pwsh.exe") and (it.get("encoded") or _ENCODED.search(args)):
            sev, note = "high", "難読化（-EncodedCommand）された PowerShell を起動している常駐。マルウェアの典型パターン"
        elif base in SCRIPT_HOSTS:
            sev, note = "medium", f"{base} 経由でスクリプトを起動している常駐。マルウェアがよく使う方法"
        elif system and "\\users\\" in low:
            sev, note = "high", "SYSTEM権限のサービスなのに、ユーザーフォルダ内のプログラムを起動している（すり替えで乗っ取られる）"
        elif re.match(r"^[a-z]:\\", low) and not Path(exe).exists():
            sev, note = "low", "起動先のファイルが存在しない（アンインストールの残骸）"
        elif system and unquoted:
            sev, note = "low", "SYSTEM権限のサービスのパスが引用符なしで空白を含む（途中のフォルダに書き込めると乗っ取られる古典的な穴）"
        detail = (note + "\n" if note else "") + f"起動: {redact(exe)[:260]}（引数は秘密が入りうるので記録しない）" + (f"\n実行アカウント: {account}" if account else "")
        target = f"{KIND_JA.get(kind, kind)} {where}\\{name}" if kind in ("run", "task", "startup") else f"サービス {name}"
        fix = ("心当たりがなければ、タスクマネージャーの「スタートアップ アプリ」・services.msc・タスクスケジューラで無効化し、"
               "Windows セキュリティでフルスキャンする") if sev != "info" else ""
        r.add(M, sev, f"常駐プログラム: {name}", target, detail, fix, key=f"wstart|{kind}|{'' if kind == 'service' else where}|{name}")
