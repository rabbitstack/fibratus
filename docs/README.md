# Documentation

The **`docs/` directory** serves as the canonical source of all user-facing documentation. It contains Markdown files that are not merely static content, but structured inputs consumed by Fibratus’ custom [documentation](https://fibratus.io/docs) engine, which powers the website experience.

At a high level, this directory is designed to balance **readability for contributors** with **rich rendering capabilities** on the site. While everything is written in Markdown, the files follow conventions and include custom extensions that the rendering engine interprets to produce a more dynamic and navigable documentation UI.

### Purpose and Structure

The `docs/` directory organizes documentation into logical sections such as:

* **Getting started** (installation, quickstart guides)
* **Core concepts** (filaments, telemetry, rules engine)
* **Configuration** (YAML/CLI flags, environment setup)
* **Reference material** (field descriptions, functions, operators)

Each section is typically represented as a subdirectory, with Markdown files forming individual pages. File names and folder hierarchy directly map to the website’s routing and sidebar navigation.

### Custom Markdown Extensions

Although the files use standard Markdown syntax, they also leverage custom directives and components understood by the Fibratus documentation engine. These may include:

* **Admonitions** (e.g., notes, warnings, tips)
* **Code block enhancements** with syntax highlighting tailored to Fibratus DSLs
* **Cross-references** that resolve to internal documentation links

### Linking and Navigation

Internal links between documents are written using relative paths, but the engine resolves and validates them at build time. It also:

* Builds the **sidebar tree** from directory structure
* Generates **breadcrumbs and navigation controls**
* Ensures **consistent URL routing** across the site
