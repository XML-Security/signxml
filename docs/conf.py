import os

project = "signxml"
copyright = "Andrey Kislyuk and signxml contributors"
author = "Andrey Kislyuk"
version = ""
release = ""
language = "en"
master_doc = "index"
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
    "sphinxext.opengraph",
]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
pygments_style = "sphinx"
autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "lxml": ("https://lxml.de/apidoc", "https://lxml.de/apidoc/objects.inv"),
    "Cryptography": ("https://cryptography.io/en/latest", "https://cryptography.io/en/latest/objects.inv"),
}
templates_path = [""]
ogp_site_url = "https://xml-security.github.io/" + project

if "readthedocs.org" in os.getcwd().split("/"):
    with open("index.rst", "w") as fh:
        fh.write("Documentation for this project has moved to https://xml-security.github.io/" + project)
else:
    html_theme = "furo"
    html_sidebars = {
        "**": [
            "sidebar/brand.html",
            "sidebar/search.html",
            "sidebar/scroll-start.html",
            "toc.html",
            "sidebar/scroll-end.html",
        ]
    }
