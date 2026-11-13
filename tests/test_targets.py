"""The deployment files and the config must agree.

A port that exists in one place and not the other produces a target that looks
closed for no visible reason, which is an afternoon lost to the wrong question.
These checks are plain text on purpose: no YAML parser is a dependency of this
project.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from honeytell.config import load

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"
GATEWAY = "10.88.0.1"

# Targets with deployment files today. The rest are in the config as the study
# design and are reported closed until they are built.
DEPLOYED = {
    "real": TARGETS / "real" / "compose.yml",
    "cowrie": TARGETS / "cowrie" / "compose.yml",
    "beelzebub": TARGETS / "beelzebub" / "compose.yml",
    "deceive": TARGETS / "deceive" / "compose.yml",
}


@pytest.fixture(scope="module")
def cfg():
    return load(ROOT / "honeytell.toml")[0]


class TestComposeFiles:
    @pytest.mark.parametrize("name", sorted(DEPLOYED))
    def test_compose_exists(self, name):
        assert DEPLOYED[name].is_file()

    @pytest.mark.parametrize("name", sorted(DEPLOYED))
    def test_every_configured_port_is_published(self, cfg, name):
        target = cfg.target(name)
        text = DEPLOYED[name].read_text()
        for backend in (target.backends or [None]):
            port = target.port_for(backend)
            assert f"127.0.0.1:{port}:" in text, (
                f"{name}/{backend} is configured on port {port}, which "
                f"{DEPLOYED[name].name} does not publish"
            )

    @pytest.mark.parametrize("name", sorted(DEPLOYED))
    def test_published_ports_are_loopback_only(self, name):
        text = DEPLOYED[name].read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if re.match(r'^-\s*"[\d.]*:?\d+:\d+"', stripped):
                assert stripped.startswith('- "127.0.0.1:'), (
                    f"{DEPLOYED[name].name} publishes {stripped} beyond loopback"
                )

    @pytest.mark.parametrize("name", sorted(DEPLOYED))
    def test_every_target_shares_one_network(self, name):
        text = DEPLOYED[name].read_text()
        assert "honeytell-lab" in text, (
            f"{name} is not on the lab network, so its path differs from the "
            f"other targets and could explain a detection on its own"
        )
        assert "external: true" in text


class TestBackendWiring:
    def test_beelzebub_configs_point_at_the_gateway(self, cfg):
        for backend in cfg.target("beelzebub").backends:
            path = TARGETS / "beelzebub" / backend / "services" / "ssh.yaml"
            assert path.is_file(), f"no service config for beelzebub/{backend}"
            text = path.read_text()
            assert f"http://{GATEWAY}:11434" in text, "must not point at localhost"
            assert 'llmProvider: "ollama"' in text
            assert cfg.backend(backend).model in text

    def test_deceive_passes_the_configured_model(self, cfg):
        text = (TARGETS / "deceive" / "compose.yml").read_text()
        for backend in cfg.target("deceive").backends:
            assert cfg.backend(backend).model in text
        assert f"http://{GATEWAY}:11434" in text
        assert '"-l", "ollama"' in text

    def test_deceive_history_fits_the_declared_context(self, cfg):
        """Sending more history than the window holds makes the server
        truncate it, which would be our setup showing up in the results."""
        text = (TARGETS / "deceive" / "compose.yml").read_text()
        trimmer = int(re.search(r'"-t", "(\d+)"', text).group(1))
        for backend in cfg.target("deceive").backends:
            assert trimmer < cfg.backend(backend).context_length


class TestPinnedSources:
    def test_fetch_script_pins_the_configured_commits(self, cfg):
        script = (TARGETS / "fetch-sources.sh").read_text()
        for name in ("cowrie", "beelzebub", "deceive"):
            commit = cfg.target(name).commit
            assert commit, f"{name} declares no commit in honeytell.toml"
            assert commit in script, (
                f"fetch-sources.sh does not pin {name} to {commit[:12]}, so the "
                f"container would not match what the report records"
            )

    def test_checkouts_are_not_tracked(self):
        assert "targets/*/src/" in (ROOT / ".gitignore").read_text()
