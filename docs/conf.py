import os

project = "signxml"
copyright = "Andrey Kislyuk and signxml contributors"
author = "Andrey Kislyuk"
version = ""
release = ""
language = "en"
master_doc = "index"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.viewcode", "sphinx.ext.intersphinx"]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
pygments_style = "sphinx"
autodoc_member_order = "bysource"
autodoc_typehints = "description"
typehints_fully_qualified = True
always_document_param_types = True
intersphinx_mapping = {
    "https://docs.python.org/3": None,
    "https://lxml.de/apidoc": "https://lxml.de/apidoc/objects.inv",
    "https://cryptography.io/en/latest": "https://cryptography.io/en/latest/objects.inv",
    "https://www.pyopenssl.org/en/stable": "https://www.pyopenssl.org/en/stable/objects.inv",
}

if "readthedocs.org" in os.getcwd().split("/"):
    with open("index.rst", "w") as fh:
        fh.write("Documentation for this project has moved to https://xml-security.github.io/" + project)
else:
    import guzzle_sphinx_theme

    html_theme_path = guzzle_sphinx_theme.html_theme_path()
    html_theme = "guzzle_sphinx_theme"
    html_theme_options = {
        "project_nav_name": project,
        "projectlink": "https://github.com/XML-Security/" + project,
    }
    html_sidebars = {
        "**": [
            "logo-text.html",
            # "globaltoc.html",
            "localtoc.html",
            "searchbox.html",
        ]
    }
