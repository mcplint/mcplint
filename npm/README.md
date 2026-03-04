# @mcplint/cli

Static security analyzer for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) configurations.

This is an npm wrapper around the [mcplint](https://github.com/mcplint/mcplint) binary.

## Usage

```sh
npx @mcplint/cli scan ./my-config.json
npx @mcplint/cli scan . --fail-on high --format sarif
```

### Install globally

```sh
npm install -g @mcplint/cli
mcplint scan .
```

See the [mcplint repository](https://github.com/mcplint/mcplint) for full documentation.
