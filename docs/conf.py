import os
import sys

sys.path.insert(0, os.path.abspath("../src"))

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "vault-autopilot"
copyright = "2024, hqdncw"
author = "hqdncw"
release = "0.1.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

suppress_warnings = ["autosectionlabel.*"]

extensions = [
    "sphinx.ext.napoleon",
    "sphinx.ext.autosectionlabel",
    # "autoapi.extension",
    # "sphinx.ext.autodoc",
    "sphinx_prompt",
    "sphinx_sitemap",
    "sphinx_inline_tabs",
    "sphinx_togglebutton",
    "sphinx_click",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_baseurl = "https://hqdncw.github.io/vault-autopilot"
html_theme = "furo"
html_title = f"{project} documentation v{release}"
htmlhelp_basename = "vault-autopilot-releasedoc"

# These folders are copied to the documentation's HTML output
html_static_path = ["_static"]

# autoapi_dirs = ["./../src/vault_autopilot/"]
# autoapi_python_use_implicit_namespaces = True
# autoapi_keep_files = True
