"""MainWindow behaviour: asking the user to trust download hosts and redirects."""

from __future__ import annotations

from qbit_plugin_dl.catalog import (
    Plugin,
)
from qbit_plugin_dl.fetch import (
    FetchError,
    trust_key_for_url,
    trust_key_label,
    untrusted_hosts_in_urls,
)
from qbit_plugin_dl.gui.dialogs import TrustPromptDialog
from qbit_plugin_dl.gui.settings import (
    add_trusted_download_host,
    trusted_download_hosts,
)


class TrustMixin:
    """Trust prompts for untrusted hosts and redirect targets."""

    def _effective_trusted_hosts(self, *, install: bool) -> set[str]:
        hosts = trusted_download_hosts() | self._session_trusted_hosts
        if not install:
            hosts |= self._session_read_trusted_hosts
        return hosts

    def _prompt_untrusted_hosts(
        self,
        plugins: list[Plugin],
        *,
        purpose: str = "install",
        required: bool = True,
    ) -> bool:
        """
        Pre-prompt for non-allowlisted trust keys on catalog URLs.

        Trust keys are ``prefix:owner/project`` for code-hosting URLs (GitHub,
        gist, Codeberg, GitLab), or a hostname for other HTTPS downloads. When *required* is True (install), Cancel
        aborts. When False (categories / updates), Cancel continues without
        trusting new keys.
        """
        unknown = untrusted_hosts_in_urls(
            (p.download_url for p in plugins),
            trusted_hosts=self._effective_trusted_hosts(install=required),
        )
        if not required:
            unknown = [h for h in unknown if h not in self._declined_download_hosts]
        if not unknown:
            return True

        examples: list[str] = []
        for key in unknown:
            label = trust_key_label(key)
            for plugin in plugins:
                if trust_key_for_url(plugin.download_url) == key:
                    examples.append(f"{label}\n  e.g. {plugin.download_url}")
                    break
            else:
                examples.append(label)

        approved = self._confirm_trust_keys(
            unknown,
            title="Untrusted download sources",
            text=(
                "Some plugins download from sources that are not on the "
                "built-in allowlist (qbittorrent/search-plugins and "
                "LightDestory/qBittorrent-Search-Plugins on "
                "raw.githubusercontent.com)."
            ),
            question=f"Approve to continue this {purpose}?",
            entries=examples,
            required=required,
        )
        # Optional (read-only) fetches continue without the new sources.
        return approved or not required

    def _confirm_trust_keys(
        self,
        keys: list[str],
        *,
        title: str,
        text: str,
        question: str,
        entries: list[str],
        required: bool = True,
    ) -> bool:
        """
        Ask Trust once / Always trust / Cancel for *keys*; record the choice.

        Returns True only when the user approved. *required* picks install vs
        read-only scope for "Trust once"; read-only declines are remembered.
        """
        dialog = TrustPromptDialog(title, text, question, entries, parent=self)
        dialog.exec()
        choice = dialog.choice
        if choice == TrustPromptDialog.ONCE:
            if required:
                self._session_trusted_hosts.update(keys)
            else:
                self._session_read_trusted_hosts.update(keys)
            self._declined_download_hosts.difference_update(keys)
            return True
        if choice == TrustPromptDialog.ALWAYS:
            for key in keys:
                add_trusted_download_host(key)
            self._declined_download_hosts.difference_update(keys)
            return True
        if not required:
            self._declined_download_hosts.update(keys)
        return False

    def _prompt_redirect_trust(
        self,
        items: list[tuple[Plugin, FetchError]],
        *,
        purpose: str = "install",
        required: bool = True,
    ) -> list[Plugin]:
        """
        Ask to approve sources that downloads were redirected to.

        Returns the plugins to retry (empty when the user cancels). The catalog
        URL was already approved; the redirect lands on a different project or
        host (e.g. a renamed GitLab namespace), which needs its own consent.
        Read-only purposes (*required* False) use read-scoped "Trust once" and
        never re-ask about sources the user declined this session.
        """
        trusted = self._effective_trusted_hosts(install=required)
        keys: list[str] = []
        lines: list[str] = []
        retry: list[Plugin] = []
        for plugin, err in items:
            if not required and err.trust_key in self._declined_download_hosts:
                continue
            retry.append(plugin)
            if err.trust_key in trusted:
                continue  # approved meanwhile (e.g. by an earlier row)
            if err.trust_key not in keys:
                keys.append(err.trust_key)
            lines.append(
                f"{plugin.name}: {trust_key_label(err.trust_key)}\n"
                f"  from {plugin.download_url}\n"
                f"  to   {err.blocked_url}"
            )
        if not retry:
            return []
        if keys and not self._confirm_trust_keys(
            keys,
            title="Download redirected",
            text=(
                "Some plugins redirected to a different source than the one "
                "you approved. A redirect can mean the project moved, or that "
                "the original location now points somewhere else."
            ),
            question=f"Approve the new source and retry the {purpose}?",
            entries=lines,
            required=required,
        ):
            return []
        return retry

    def _redirect_items(
        self,
        redirects: dict[str, FetchError],
        plugins: list[Plugin],
    ) -> list[tuple[Plugin, FetchError]]:
        by_url = {p.download_url: p for p in plugins}
        return [
            (by_url[url], err) for url, err in redirects.items() if url in by_url
        ]
