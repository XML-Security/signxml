"""Hook for pyinstaller to include the files are signxml/schemas/* into the final build."""

# PyInstaller requires hook filenames to use the hook-<module>.py convention.
# ruff: noqa: N999

from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("signxml", excludes=["__pyinstaller"])
