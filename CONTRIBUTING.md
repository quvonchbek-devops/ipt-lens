# Contributing to IPT-Lens

Thanks for your interest. IPT-Lens changes firewalls on real servers, so the bar
for correctness is high. Changes are welcome, but they should be small, tested and
easy to review.

## Before you start

- For anything bigger than a small fix, open an issue first and describe the
  problem. That saves you from building something that will not be merged.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need Go 1.21 or newer. No root is needed for development.

```sh
make demo     # run with sample data at http://127.0.0.1:8090
make test     # go vet + go test
make race     # tests with the race detector
make lint     # gofmt check, vet, staticcheck
```

The frontend is plain HTML, CSS and JavaScript in `web/dist/`, embedded into the
binary. There is no build step; rebuild or rerun the Go binary to see changes.

Code that runs `iptables` goes through the `runIPT`, `runSave` and `runSaveRules`
variables in `internal/iptables/exec.go`. Tests replace them (see
`installFake` in `watchdog_test.go`), so you can test firewall changes without
touching your machine. Never run tests that change the host firewall.

To try against a real firewall, use a throwaway VM or container with
`CAP_NET_ADMIN`, never your workstation or a server you care about.

## Pull requests

- One logical change per pull request.
- Add a test that fails without your change. Bug fixes need a regression test.
- Run `make lint race` before pushing. CI runs the same checks.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for messages:
  `fix(simulator): ...`, `feat(api): ...`, `docs: ...`.
- Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for any
  user-visible change.
- Write UI text from the user's side: buttons say what they do, errors say what
  went wrong and how to fix it.

## Design rules worth knowing

- **Never use a shell.** Rule text is validated and passed to `exec` as arguments.
  New options go into the allowlists in `internal/iptables/validate.go`.
- **Every change needs an exact undo.** A change is a list of steps; each step's
  undo reverses exactly that step.
- **Never touch managed chains.** Docker, Kubernetes, Calico, libvirt and ufw own
  their chains. The protected list lives in `internal/iptables/rules.go` and is
  mirrored in `web/dist/app.js`.
- **Be honest in the simulator.** If something cannot be evaluated, say so in the
  result rather than guessing silently.

More detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Releasing (maintainers)

1. Move the `Unreleased` entries in `CHANGELOG.md` to a new version section.
2. Tag: `git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0`.
3. The release workflow builds the archives and creates a draft release.
   Review it and publish.
