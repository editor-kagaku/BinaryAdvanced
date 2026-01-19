import argparse
import datetime
import ipaddress
import sys
import glibc_utmp

# 表示する全ての項目
ATTRIBUTES = ("ut_type", "pid", "line", "id", "user", "host", "exit", "session", "tv", "addr_v6")
# デフォルトで表示する項目
ATTRIBUTES_DEFAULT = ("ut_type", "pid", "line", "user", "host", "tv", "addr_v6")

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
        for a in attr:
            output += f"{str(getattr(record, a)).ljust(width[a] + 2)}"
        print(output)
