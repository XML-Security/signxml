# Agent guidance

- Do not edit `Changes.rst`; it is generated automatically by the release machinery.
- Do not customize Sphinx autodoc configuration or directives to list individual symbols or member lists. All autodoc configuration must be generic.
- Public APIs must be documented. Private modules, classes, and helper functions must use an underscore prefix.
- Do not use `__all__` to control which symbols get exported.
