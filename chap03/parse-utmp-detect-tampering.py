import argparse
import datetime
import ipaddress
import os
import sys
import glibc_utmp

# 表示する全ての項目
ATTRIBUTES = ("ut_type", "pid", "line", "id", "user", "host", "exit", "session", "tv", "addr_v6")
# デフォルトで表示する項目
ATTRIBUTES_DEFAULT = ("ut_type", "pid", "line", "user", "host", "tv", "addr_v6")
# 改ざん検知のメッセージの最大幅
MESSAGE_WIDTH = 114

# パースした結果の各項目を処理する関数
def process_records(utmp: glibc_utmp.GlibcUtmp, utc: bool) -> glibc_utmp.GlibcUtmp:
    for record in utmp.records:
        # ut_typeの文字列での表記(run_lvl等)をrecord.ut_typeで参照できるようにする
        record.ut_type = record.ut_type.name if hasattr(record.ut_type, "name") else record.ut_type

        # パースした結果の文字列のNULLバイト以降を削除する
        record.line = record.line.split("\x00")[0]
        record.id = record.id.split("\x00")[0]
        record.user = record.user.split("\x00")[0]
        record.host = record.host.split("\x00")[0]

        # ut_typeがrun_lvlで、pidが0以外の場合はpidをランレベルの文字に変換する
        if record.ut_type == "run_lvl":
            if record.pid == 0:
                record.pid = f"lvl0"
            else:
                record.pid = f"lvl{chr(record.pid)}"

        # tvとaddr_v6を文字列に変換する
        record.tv = convert_tv(record.tv, utc)
        record.addr_v6 = convert_addr_v6(record.addr_v6)

    return utmp

# tvを日時の文字列に変換する関数
def convert_tv(tv: glibc_utmp.GlibcUtmp.Timeval, utc: bool) -> str:
    # UNIX epochは1970-01-01 00:00:00(UTC)
    epoch = datetime.datetime(year=1970, month=1, day=1, tzinfo=datetime.timezone.utc)

    # tvにはUNIX epochからの経過時間が秒(tv.sec)とマイクロ秒(tv.usec)で
    # 記録されているので、この値からtimedeltaオブジェクトを作成する
    delta = datetime.timedelta(seconds=tv.sec, microseconds=tv.usec)

    # UNIX epochの日時にtvの経過時間を加算してタイムスタンプを計算し、
    # タイムゾーンをUTCにしない場合はastimezone()でこのスクリプトを実行
    # しているマシンのタイムゾーンに合わせて変換する
    if utc:
        stamp = epoch + delta
    else:
        stamp = (epoch + delta).astimezone()

    # タイムスタンプを2024-05-03 19:47:03.166658 JSTのような形式の
    # 日時の文字列に変換する
    return stamp.strftime("%Y-%m-%d %H:%M:%S.%f %Z")

# addr_v6のバイト列を文字列に変換する関数
# 先頭4バイトまでのみに値がある場合はIPv4アドレスとして解釈する
def convert_addr_v6(addr_v6: bytes) -> str:
    empty = True
    v6 = False
    # 5バイト目以降の値の有無でIPv4アドレスとIPv6アドレスを判別する
    for i in range(4, len(addr_v6)):
        if addr_v6[i] != 0:
            empty = False
            v6 = True
            break

    # 先頭4バイトのデータの有無の確認
    for i in range(0, 4):
        if addr_v6[i] != 0:
            empty = False
            break

    # 全てNULLバイト("\x00")でデータがない場合は空文字列を返す
    if empty:
        return ""

    if v6:
        # IPv6アドレスに変換する
        return ipaddress.IPv6Address(addr_v6)
    else:
        # IPv4アドレスに変換する
        return ipaddress.IPv4Address(addr_v6[:4])

# 各項目の最大の幅を計算する関数
def count_width(records: list) -> dict:
    # 各項目名の幅を初期値とする
    width = {}
    for a in ATTRIBUTES:
        width[a] = len(a)

    for r in records:
        for a in ATTRIBUTES:
            # getattr(r, "ut_type")はr.ut_typeと等価
            if len(str(getattr(r, a))) > width[a]:
                width[a] = len(str(getattr(r, a)))

    return width

# 履歴の改ざんを検知する関数
# 改ざんが検知された場合はtamperedの属性にメッセージを追加する
def detect_tampering(utmp: glibc_utmp.GlibcUtmp) -> glibc_utmp.GlibcUtmp:
    pid_max = 4194304
    tv_prev = 0
    entry_type = glibc_utmp.GlibcUtmp.EntryType

    for i in range(len(utmp.records)):
        utmp.records[i].tampered = ""

        # ut_typeがEntryTypeの範囲外の値である場合は改ざんされていると判定する
        if type(utmp.records[i].ut_type) != entry_type:
            utmp.records[i].tampered += format_tampering_message(f"invalid ut_type {utmp.records[i].ut_type}")

        # pidが最大値より大きい値または負の値である場合は改ざんされていると判定する
        if utmp.records[i].pid > pid_max or utmp.records[i].pid < 0:
            utmp.records[i].tampered += format_tampering_message(f"invalid pid (> {pid_max} or < 0)")

        # 常に何か文字列が入っているはずのlineが空である、または空白文字で埋められている場合は
        # 改ざんされていると判定する
        if utmp.records[i].line.split("\x00")[0] == "":
            utmp.records[i].tampered += format_tampering_message("empty line")
        elif utmp.records[i].line.split("\x00")[0].isspace():
            utmp.records[i].tampered += format_tampering_message("line filled with spaces")
            # 改行やタブで埋められた場合に出力が乱れないようにlineを空にする
            utmp.records[i].line = ""

        # idが空白文字で埋められている場合は改ざんされていると判定する
        if utmp.records[i].id.split("\x00")[0].isspace():
            utmp.records[i].tampered += format_tampering_message("id filled with spaces")
            # 改行やタブで埋められた場合に出力が乱れないようにidを空にする
            utmp.records[i].id = ""

        # userが空白文字で埋められている場合、またはut_typeがinit_processとdead_process以外で
        # userが空である場合は改ざんされていると判定する
        if utmp.records[i].user.split("\x00")[0].isspace():
            utmp.records[i].tampered += format_tampering_message("user filled with spaces")
            # 改行やタブで埋められた場合に出力が乱れないようにuserを空にする
            utmp.records[i].user = ""
        elif not utmp.records[i].ut_type in (entry_type.init_process, entry_type.dead_process) \
           and utmp.records[i].user.split("\x00")[0] == "":
            utmp.records[i].tampered += format_tampering_message("empty user")

        # hostが空白文字で埋められている場合は改ざんされていると判定する
        if utmp.records[i].host.split("\x00")[0].isspace():
            utmp.records[i].tampered += format_tampering_message("host filled with spaces")
            # 改行やタブで埋められた場合に出力が乱れないようにhostを空にする
            utmp.records[i].host = ""

        # 前の履歴のタイムスタンプと現在の履歴のタイムスタンプを比較して1秒より大きい場合はタイム
        # スタンプが改ざんされていると判定する。同時に複数の履歴を書き込んだ場合などにマイクロ秒
        # 単位でタイムスタンプが逆転する場合があり、この場合は改ざんと判定しない。
        tv_current = utmp.records[i].tv.sec
        if tv_prev > tv_current + 1:
            utmp.records[i].tampered += format_tampering_message("timestamp going backwards")

        tv_prev = tv_current

        # sessionが最大値より大きい値または負の値である場合は改ざんされていると判定する
        if utmp.records[i].session > pid_max or utmp.records[i].session < 0:
            utmp.records[i].tampered += format_tampering_message(f"invalid session (> {pid_max} or < 0)")

        # ut_typeがuser_processでaddr_v6に値があるのにhostが空の場合は改ざんされていると判定する
        if utmp.records[i].host.split("\x00")[0] == "" \
           and utmp.records[i].addr_v6 != b"\x00" * 16:
            utmp.records[i].tampered += format_tampering_message("empty host with non-empty addr_v6")

    return utmp

# 改ざん検知のメッセージをフォーマットする関数
def format_tampering_message(message: str) -> str:
    formatted = "*" * 34 + f" Tampering detected: {message} " + "*" * (MESSAGE_WIDTH - len(message) - 56) + "\n"

    return formatted

# utmpファイルの最終更新日時と最も新しい履歴のタイムスタンプを比較する関数
def check_timestamp(filepath: str, utmp: glibc_utmp.GlibcUtmp, utc: bool) -> bool:
    # utmpファイルの最終更新日時を取得する
    utmp_mtime = os.path.getmtime(filepath)

    # 最も新しい履歴のタイムスタンプを取得する
    tv_latest = utmp.records[-1].tv.sec + utmp.records[-1].tv.usec / 1000000

    # タイムゾーンに応じてタイムスタンプを日時の文字列に変換する
    if utc:
        utmp_mtime_datetime = datetime.datetime.fromtimestamp(utmp_mtime, tz=datetime.timezone.utc)
        utmp_mtime_str = utmp_mtime_datetime.strftime("%Y-%m-%d %H:%M:%S.%f %Z")
        tv_latest_datetime = datetime.datetime.fromtimestamp(tv_latest, tz=datetime.timezone.utc)
        tv_latest_str = tv_latest_datetime.strftime("%Y-%m-%d %H:%M:%S.%f %Z")
    else:
        utmp_mtime_datetime = datetime.datetime.fromtimestamp(utmp_mtime).astimezone()
        utmp_mtime_str = utmp_mtime_datetime.strftime("%Y-%m-%d %H:%M:%S.%f %Z")
        tv_latest_datetime = datetime.datetime.fromtimestamp(tv_latest).astimezone()
        tv_latest_str = tv_latest_datetime.strftime("%Y-%m-%d %H:%M:%S.%f %Z")

    # タイムスタンプを比較する
    if utmp_mtime - tv_latest > 1:
        return (True, utmp_mtime_str, tv_latest_str)
    else:
        return (False, utmp_mtime_str, tv_latest_str)

if __name__ == "__main__":
    # オプションや引数の処理
    ap = argparse.ArgumentParser()
    # 引数でファイルのパスを受け取り、filepathに格納する
    ap.add_argument("filepath", help="処理するファイルのパス")
    # -fオプションが指定された場合は全ての項目を出力する
    ap.add_argument("-f",
                    dest="display_full",
                    help="全ての項目を出力する",
                    action="store_true")
    # -uオプションが指定された場合はutcにTrueを格納する
    ap.add_argument("-u",
                    dest="utc",
                    help="UTCのタイムゾーンでタイムスタンプを出力する",
                    action="store_true")
    args = ap.parse_args()

    try:
        # 引数で指定されたファイルを読み込む
        with open(args.filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        # ファイルを読み込めなかった場合はエラーメッセージを出力して終了する
        print(e)
        sys.exit(1)

    # glibc_utmpモジュールでdataをパースする
    utmp = glibc_utmp.GlibcUtmp.from_bytes(data)

    # utmpファイルの最終更新日時と最も新しい履歴のタイムスタンプを比較する
    (modified, utmp_mtime_str, tv_latest_str) = check_timestamp(args.filepath, utmp, args.utc)

    # 履歴の改ざんを検知する
    utmp = detect_tampering(utmp)

    # パースした結果の各項目を処理する
    utmp = process_records(utmp, args.utc)

    # 各項目の最大の幅を計算する
    width = count_width(utmp.records)

    # -fオプションが指定された場合は全ての項目を出力する
    if args.display_full:
        attr = ATTRIBUTES
    else:
        attr = ATTRIBUTES_DEFAULT

    # パースした結果を各項目の最大の幅に合わせて左揃えで出力する
    output = ""
    for a in attr:
        output += f"{a.ljust(width[a] + 2)}"
    print(output)

    for record in reversed(utmp.records):
        output = ""
        # 履歴の改ざんを検知した場合はメッセージを追加する
        if record.tampered != "":
            output += record.tampered

        for a in attr:
            output += f"{str(getattr(record, a)).ljust(width[a] + 2)}"

        # 改ざんのメッセージと同じ行数の"******"の行を追加する
        if record.tampered != "":
            for i in range(len(record.tampered.splitlines())):
                output += "\n" + "*" * len(record.tampered.splitlines()[i])

        print(output)

    # utmpファイルの最終更新日時が最も新しい履歴のタイムスタンプよりも新しい場合は
    # 改ざんの可能性があるため警告のメッセージを表示する
    if modified:
        print("\n"+ "*" * MESSAGE_WIDTH)
        print(f"Warning: The utmp file was modified after the last record was written.")
        print(f"utmp file last modified: {utmp_mtime_str}")
        print(f"Last record timestamp: {tv_latest_str}")
        print("*" * MESSAGE_WIDTH + "\n")
