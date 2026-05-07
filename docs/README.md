# SCCAP Documentation

Built with [MkDocs](https://www.mkdocs.org/) + [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/).

## Local preview

```bash
cd docs
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-docs.txt
mkdocs serve
```

Open http://127.0.0.1:8000/ — pages reload on save.

## Production build

```bash
cd docs
mkdocs build --strict
```

Static output is written to `docs/site/` (gitignored). Deploy that directory to any static host (GitHub Pages, S3, CloudFront, Netlify, …). For GitHub Pages auto-publish:

```bash
mkdocs gh-deploy --strict
```

## Authoring

- Prose lives under `docs/docs/`. Each file becomes a page; the URL is the path with `.md` stripped.
- Navigation order is set in `mkdocs.yml` under `nav:`. Rearrange there, not via filename prefixes.
- Admonitions use Material's syntax (note the 4-space indent on body lines):

  ```markdown
  !!! info "Optional title"

      Body of the admonition. Indented with four spaces.
  ```

  Supported types: `note`, `tip`, `info`, `warning`, `danger`, `success`, `question`, `quote`, `example`, `bug`, `failure`, `abstract`.

- Code fences with language identifiers get syntax highlighting via Pygments. Mermaid diagrams work via PyMdown's superfences:

  ````markdown
  ```mermaid
  graph LR
    A --> B
  ```
  ````

- Tabs (PyMdown `pymdownx.tabbed`):

  ```markdown
  === "Linux"

      ```bash
      ./setup.sh
      ```

  === "Windows"

      ```powershell
      .\setup.ps1
      ```
  ```

## Configuration reference

- `mkdocs.yml` — site config, theme, navigation, markdown extensions.
- `requirements-docs.txt` — pinned Python deps for the docs build.

For the full theme reference see <https://squidfunk.github.io/mkdocs-material/>.
