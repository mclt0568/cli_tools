import os
import stat
import pathlib
import magic
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("path", nargs='*', default=["."])
parser.add_argument("-a", "--all", action="store_true")
parser.add_argument("-f", "--fields")
args = parser.parse_args()


FG_ORANGE = "\033[38;5;216m"
FG_BLUE = "\033[38;5;153m"
FG_GREEN = "\033[38;5;157m"
FG_RED = "\033[38;5;215m"
FG_LAVENDAR = "\033[38;5;183m"
FG_WHITE = "\033[38;5;254m"
FG_GRAY = "\033[38;5;240m"
RESET = "\033[0m"


PERM_HAS_R = FG_WHITE+"r"+RESET
PERM_HAS_W = FG_WHITE+"w"+RESET
PERM_HAS_X = FG_WHITE+"x"+RESET
PERM_HAS_S = FG_WHITE+"s"+RESET
PERM_HAS_SX = FG_WHITE+"S"+RESET
PERM_MIS_R = FG_GRAY+"."+RESET
PERM_MIS_W = FG_GRAY+"."+RESET
PERM_MIS_X = FG_GRAY+"."+RESET


SYMBOLS = {
  "dir":        f"{FG_BLUE}󰉋 ",
  "dir_hidden": f"{FG_BLUE}󱞞 ",
  "special":    f"{FG_LAVENDAR} ",
  "block":      f"{FG_LAVENDAR}󰆦 ",
  "pipe":       f"{FG_LAVENDAR}󰟥 ",
  "socket":     f"{FG_LAVENDAR}󰟨 ",
  "symlink":    f"{FG_GREEN} ",

  "file":       f"{FG_WHITE}󰈔 ",
  "file_hidden":f"{FG_WHITE}󰘓 ",
  "binary":     f"{FG_WHITE} ",
  "exec":       f"{FG_ORANGE}󰩃 ",
  "script":     f"{FG_ORANGE}󰄛 ",
}


def is_dir(result: os.stat_result) -> bool:
  return stat.S_ISDIR(result.st_mode)


def decide_symbol(filename: str, result: os.stat_result) -> str:
  pure_name = pathlib.PurePath(filename).name
  
  if pathlib.Path(filename).is_symlink():
    return SYMBOLS["symlink"]
  
  if is_dir(result):
    return SYMBOLS["dir_hidden" if pure_name[0] == "." else "dir"]
  
  if stat.S_ISBLK(result.st_mode):
    return SYMBOLS["block"]
  
  if stat.S_ISSOCK(result.st_mode):
    return SYMBOLS["socket"]
  
  if stat.S_ISCHR(result.st_mode):
    return SYMBOLS["special"]
  
  if not stat.S_ISREG(result.st_mode):
    return SYMBOLS["file_hidden" if pure_name[0] == "." else "file"]
  
  mime = str(magic.from_file(filename, mime=True))

  match mime:
    case "application/x-pie-executable":
      return SYMBOLS["exec"]
    case "text/x-shellscript":
      return SYMBOLS["script"]
    case "application/octet-stream":
      return SYMBOLS["binary"]
  
  return SYMBOLS["file_hidden" if pure_name[0] == "." else "file"]


def get_permission(result: os.stat_result) -> str:
  mode = result.st_mode
  
  user_read = PERM_HAS_R if stat.S_IRUSR & mode else PERM_MIS_R
  user_write = PERM_HAS_W if stat.S_IWUSR & mode else PERM_MIS_W
  user_exec = PERM_HAS_X if stat.S_IXUSR & mode else PERM_MIS_X
  user_has_exec = user_exec != PERM_MIS_X
  user_exec = PERM_HAS_SX if (stat.S_ISUID & mode) and user_has_exec else user_exec
  user_exec = PERM_HAS_S if stat.S_ISUID & mode else user_exec
  
  group_read = PERM_HAS_R if stat.S_IRGRP & mode else PERM_MIS_R
  group_write = PERM_HAS_W if stat.S_IWGRP & mode else PERM_MIS_W
  group_exec = PERM_HAS_X if stat.S_IXGRP & mode else PERM_MIS_W
  group_has_exec = group_exec != PERM_MIS_X
  group_exec = PERM_HAS_SX if (stat.S_ISGID & mode) and group_has_exec else group_exec
  group_exec = PERM_HAS_S if stat.S_ISGID & mode else group_exec
  
  other_read = PERM_HAS_R if stat.S_IROTH & mode else PERM_MIS_R
  other_write = PERM_HAS_W if stat.S_IWOTH & mode else PERM_MIS_W
  other_exec = PERM_HAS_X if stat.S_IXGRP & mode else PERM_MIS_X

  return f"{user_read}{user_write}{user_exec}{group_read}{group_write}{group_exec}{other_read}{other_write}{other_exec}"


def form_entry(filename: str):
  stat = os.stat(filename)
  pure_name = pathlib.PurePath(filename).name
  symbol = decide_symbol(filename, stat)

  fields = {
    "filename": f"{symbol} {pure_name}{RESET}" + ("/" if is_dir(stat) else ""),
    "symbol_raw": f"{symbol}",
    "filename_raw": f"{pure_name}" + ("/" if is_dir(stat) else ""),
    "permissions": f"{get_permission(stat)}{RESET}",
  }
  
  return fields


def get_files(path: str | None = None) -> list[str]:
  base_path = pathlib.Path(path)
  files = [f for f in os.listdir(path) if (base_path / f).is_file()]

  return files


def get_dirs(path: str | None = None) -> list[str]:
  base_path = pathlib.Path(path)
  files = [f for f in os.listdir(path) if (base_path / f).is_dir()]
  return files


def main():
  path = args.path[0]
  base_path = pathlib.Path(path)


  if not os.path.exists(path):
    sys.stderr.write(f"lf: {path} does not exist\n")
    sys.stderr.flush()
    sys.exit(1)

  files = get_files(path)
  dirs = get_dirs(path)
  files.sort()
  dirs.sort()

  if not args.all:
    files = list(filter(lambda x: x[0] != ".", files))
    dirs = list(filter(lambda x: x[0] != ".", dirs))

  if args.all:
    entry = form_entry(str(base_path/"."))
    print(entry["permissions"] + "  " + f"{SYMBOLS['dir_hidden']} .{RESET}/")
    entry = form_entry(str(base_path/".."))
    print(entry["permissions"] + "  " + f"{SYMBOLS['dir_hidden']} ..{RESET}/")

  for dir in dirs:
    entry = form_entry(str(base_path/dir))
    print(entry["permissions"] + "  " + entry["filename"])

  for file in files:
    entry = form_entry(str(base_path/file))
    print(entry["permissions"] + "  " + entry["filename"])


if __name__ == "__main__":
  main()