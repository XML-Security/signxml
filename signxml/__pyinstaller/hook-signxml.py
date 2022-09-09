"""Hook for pyinstaller to include the files are signxml/schemas/* into the final build."""

from PyInstaller.utils.hooks import collect_data_files  # type: ignore

datas = collect_data_files("signxml", excludes=["__pyinstaller"])
