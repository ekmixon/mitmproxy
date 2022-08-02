import typing

import os

from mitmproxy.utils import emoji
from mitmproxy import ctx, hooks
from mitmproxy import exceptions
from mitmproxy import command
from mitmproxy import flow
from mitmproxy import optmanager
from mitmproxy import platform
from mitmproxy.net import server_spec
from mitmproxy.net.http import status_codes
import mitmproxy.types


CONF_DIR = "~/.mitmproxy"
LISTEN_PORT = 8080


class Core:
    def configure(self, updated):
        opts = ctx.options
        if opts.add_upstream_certs_to_client_chain and not opts.upstream_cert:
            raise exceptions.OptionsError(
                "add_upstream_certs_to_client_chain requires the upstream_cert option to be enabled."
            )
        if "mode" in updated:
            mode = opts.mode
            if mode.startswith("reverse:") or mode.startswith("upstream:"):
                try:
                    server_spec.parse_with_mode(mode)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
            elif mode == "transparent":
                if not platform.original_addr:
                    raise exceptions.OptionsError(
                        "Transparent mode not supported on this platform."
                    )
            elif mode not in ["regular", "socks5"]:
                raise exceptions.OptionsError(f"Invalid mode specification: {mode}")
        if "client_certs" in updated and opts.client_certs:
            client_certs = os.path.expanduser(opts.client_certs)
            if not os.path.exists(client_certs):
                raise exceptions.OptionsError(
                    f"Client certificate path does not exist: {opts.client_certs}"
                )

    @command.command("set")
    def set(self, option: str, value: str = "") -> None:
        """
            Set an option. When the value is omitted, booleans are set to true,
            strings and integers are set to None (if permitted), and sequences
            are emptied. Boolean values can be true, false or toggle.
            Multiple values are concatenated with a single space.
            Sequences are set using multiple invocations to set for
            the same option.
        """
        strspec = f"{option}={value}"
        try:
            ctx.options.set(strspec)
        except exceptions.OptionsError as e:
            raise exceptions.CommandError(e) from e

    @command.command("flow.resume")
    def resume(self, flows: typing.Sequence[flow.Flow]) -> None:
        """
            Resume flows if they are intercepted.
        """
        intercepted = [i for i in flows if i.intercepted]
        for f in intercepted:
            f.resume()
        ctx.master.addons.trigger(hooks.UpdateHook(intercepted))

    # FIXME: this will become view.mark later
    @command.command("flow.mark")
    def mark(self, flows: typing.Sequence[flow.Flow], marker: mitmproxy.types.Marker) -> None:
        """
            Mark flows.
        """
        updated = []
        if marker not in emoji.emoji:
            raise exceptions.CommandError("invalid marker value")

        for i in flows:
            i.marked = marker
            updated.append(i)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    # FIXME: this will become view.mark.toggle later
    @command.command("flow.mark.toggle")
    def mark_toggle(self, flows: typing.Sequence[flow.Flow]) -> None:
        """
            Toggle mark for flows.
        """
        for i in flows:
            i.marked = "" if i.marked else ":default:"
        ctx.master.addons.trigger(hooks.UpdateHook(flows))

    @command.command("flow.kill")
    def kill(self, flows: typing.Sequence[flow.Flow]) -> None:
        """
            Kill running flows.
        """
        updated = []
        for f in flows:
            if f.killable:
                f.kill()
                updated.append(f)
        ctx.log.alert(f"Killed {len(updated)} flows.")
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    # FIXME: this will become view.revert later
    @command.command("flow.revert")
    def revert(self, flows: typing.Sequence[flow.Flow]) -> None:
        """
            Revert flow changes.
        """
        updated = []
        for f in flows:
            if f.modified():
                f.revert()
                updated.append(f)
        ctx.log.alert(f"Reverted {len(updated)} flows.")
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    @command.command("flow.set.options")
    def flow_set_options(self) -> typing.Sequence[str]:
        return [
            "host",
            "status_code",
            "method",
            "path",
            "url",
            "reason",
        ]

    @command.command("flow.set")
    @command.argument("attr", type=mitmproxy.types.Choice("flow.set.options"))
    def flow_set(
        self,
        flows: typing.Sequence[flow.Flow],
        attr: str,
        value: str
    ) -> None:
        """
            Quickly set a number of common values on flows.
        """
        val: typing.Union[int, str] = value
        if attr == "status_code":
            try:
                val = int(val)  # type: ignore
            except ValueError as v:
                raise exceptions.CommandError(
                    "Status code is not an integer: %s" % val
                ) from v

        updated = []
        rupdate = True
        for f in flows:
            if req := getattr(f, "request", None):
                if attr == "method":
                    req.method = val
                elif attr == "host":
                    req.host = val
                elif attr == "path":
                    req.path = val
                elif attr == "url":
                    try:
                        req.url = val
                    except ValueError as e:
                        raise exceptions.CommandError(
                            "URL {} is invalid: {}".format(repr(val), e)
                        ) from e
                else:
                    self.rupdate = False

            resp = getattr(f, "response", None)
            supdate = True
            if resp:
                if attr == "status_code":
                    resp.status_code = val
                    if val in status_codes.RESPONSES:
                        resp.reason = status_codes.RESPONSES[val]  # type: ignore
                elif attr == "reason":
                    resp.reason = val
                else:
                    supdate = False

            if rupdate or supdate:
                updated.append(f)

        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        ctx.log.alert("Set {} on  {} flows.".format(attr, len(updated)))

    @command.command("flow.decode")
    def decode(self, flows: typing.Sequence[flow.Flow], part: str) -> None:
        """
            Decode flows.
        """
        updated = []
        for f in flows:
            if p := getattr(f, part, None):
                f.backup()
                p.decode()
                updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        ctx.log.alert(f"Decoded {len(updated)} flows.")

    @command.command("flow.encode.toggle")
    def encode_toggle(self, flows: typing.Sequence[flow.Flow], part: str) -> None:
        """
            Toggle flow encoding on and off, using deflate for encoding.
        """
        updated = []
        for f in flows:
            if p := getattr(f, part, None):
                f.backup()
                current_enc = p.headers.get("content-encoding", "identity")
                if current_enc == "identity":
                    p.encode("deflate")
                else:
                    p.decode()
                updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        ctx.log.alert(f"Toggled encoding on {len(updated)} flows.")

    @command.command("flow.encode")
    @command.argument("encoding", type=mitmproxy.types.Choice("flow.encode.options"))
    def encode(
        self,
        flows: typing.Sequence[flow.Flow],
        part: str,
        encoding: str,
    ) -> None:
        """
            Encode flows with a specified encoding.
        """
        updated = []
        for f in flows:
            if p := getattr(f, part, None):
                current_enc = p.headers.get("content-encoding", "identity")
                if current_enc == "identity":
                    f.backup()
                    p.encode(encoding)
                    updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))
        ctx.log.alert(f"Encoded {len(updated)} flows.")

    @command.command("flow.encode.options")
    def encode_options(self) -> typing.Sequence[str]:
        """
            The possible values for an encoding specification.
        """
        return ["gzip", "deflate", "br", "zstd"]

    @command.command("options.load")
    def options_load(self, path: mitmproxy.types.Path) -> None:
        """
            Load options from a file.
        """
        try:
            optmanager.load_paths(ctx.options, path)
        except (OSError, exceptions.OptionsError) as e:
            raise exceptions.CommandError(f"Could not load options - {e}") from e

    @command.command("options.save")
    def options_save(self, path: mitmproxy.types.Path) -> None:
        """
            Save options to a file.
        """
        try:
            optmanager.save(ctx.options, path)
        except OSError as e:
            raise exceptions.CommandError(f"Could not save options - {e}") from e

    @command.command("options.reset")
    def options_reset(self) -> None:
        """
            Reset all options to defaults.
        """
        ctx.options.reset()

    @command.command("options.reset.one")
    def options_reset_one(self, name: str) -> None:
        """
            Reset one option to its default value.
        """
        if name not in ctx.options:
            raise exceptions.CommandError(f"No such option: {name}")
        setattr(
            ctx.options,
            name,
            ctx.options.default(name),
        )
